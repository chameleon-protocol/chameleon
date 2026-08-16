package realm

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The disco demultiplexer sits ABOVE the obfuscator, which is the one thing
// about it that is not obvious:
//
//	quic.Transport
//	  └── DiscoPacketConn      ★ disco packets are taken out here
//	        └── obfs
//	              └── PunchPacketConn   punch and STUN come out here
//	                    └── *net.UDPConn
//
// The rule that puts it there is "traffic whose peer holds our pre-shared key
// goes under that key; only traffic to a third party that does not hold it
// stays outside". Disco's peer is our own server, so it goes under. STUN's peer
// is a public STUN server that has never heard of us, so it stays outside and
// keeps its demux below the obfuscator.
//
// Punch is on the wrong side of that rule today. It kept its demux below the
// obfuscator and paid for it in a different currency: its packets have to
// imitate a wire length rather than a payload length, so the sampler that
// chooses that length has to sit below the obfuscator too, and on a socket that
// has not yet carried a QUIC datagram there is nothing to sample and the packet
// falls back to a guessed band that an offline length whitelist catches at 98%.
// Disco does not have that problem and cannot acquire it: it pads to a length
// its own QUIC connection has already sent, the obfuscator adds the same
// overhead to a disco packet as to a data packet, and there is no window in
// which a legitimate disco packet exists before QUIC has sent anything, because
// the disco key comes from the TLS exporter and neither end can export before
// the handshake completes.

const (
	defaultDiscoEventBuffer = 16

	// discoEpochCheckInterval is how often the tag table is rebuilt. It has to
	// be well under discoEpoch: a receiver that noticed the epoch late would
	// have dropped the sender's packets in between, and they are not
	// retransmitted.
	discoEpochCheckInterval = 15 * time.Second

	// discoWireLenWindow is how many recent outbound lengths the padding target
	// is taken from.
	//
	// Short on purpose. The window is a claim about what this connection is
	// sending *now*, and a long one averages over a path MTU change instead of
	// following it. On a loaded connection this spans well under a second, which
	// is still far more packets than the mode needs to be stable: across the
	// captures taken so far the full-size datagram is the single most common
	// length in both directions and in both deployments by a wide margin --
	// between 40% and 67% of the flow against 11% to 21% for the runner-up --
	// and further ahead than that once the lengths under the floor below are
	// dropped. The share itself is not reproducible run to run, because it
	// depends on how the capture's paced transfer interleaves with acks; what
	// is reproducible, and all this depends on, is which length wins.
	//
	// What the length of the window buys, and the only thing that reads it, is
	// how much of a new path it takes to move the target: a bare majority of the
	// window, so about thirty datagrams here, and a minority never.
	// TestDiscoWireLenWindowTakesAMajorityToMove pins that from both sides.
	discoWireLenWindow = 64

	// discoWireLenMaxAge is how far back from a connection's most recent
	// datagram the padding target may reach.
	//
	// Without it the window has no clock at all: an application that goes idle
	// stops refreshing it, and the target ages into whatever the flow looked
	// like when it was last busy. The mixed case is the one that bites -- a long
	// run at the old path's length and then a handful at the new one -- where
	// the mode of the raw window still names the path the connection has left.
	// Ten seconds is longer than any gap an active flow leaves (the captures fit
	// 64 full-size datagrams into well under a second) and short enough that a
	// connection resuming on a new path retargets on its first few datagrams
	// rather than its sixty-fourth.
	discoWireLenMaxAge = 10 * time.Second
)

var (
	ErrInvalidDiscoSession = errors.New("invalid disco session")
	ErrUnknownDiscoSession = errors.New("unknown disco session")

	// ErrDiscoRequiresObfs is what a disco conn over a bare socket fails with.
	// There is no unobfuscated disco format: measured against a real captured
	// flow, the best candidate with no cleartext prefix at all was still caught
	// at 50% (client to server) and 24% (server to client) with a 0.00% false
	// positive rate, within the first four packets, because bare QUIC has
	// structure in its first byte and its connection ID that random bytes cannot
	// imitate and that a demultiplexable packet cannot imitate either. So a
	// missing obfuscator is a configuration error, never a downgrade.
	ErrDiscoRequiresObfs = errors.New("disco requires an obfuscator")

	// ErrDiscoRequiresSalamanderV2 is the same refusal for an obfuscator that is
	// present but was never measured.
	//
	// Disco hides by taking the length of the datagrams beside it and by being
	// sealed in a background of uniform random bytes, and the only background
	// that was ever captured is salamander v2's. Gecko is not merely unmeasured
	// but structurally wrong for this: it pads every datagram to a random size
	// drawn from a range, so there is no modal length to copy and no dense
	// bucket to hide in. Salamander v1 stretches one hash output over the whole
	// packet, which is what it was retired for.
	//
	// app/cmd/realm_punch_mask.go settled the identical question for punching.
	// Disco matches it rather than inventing a second answer, and refuses at
	// startup: a deployment that believes it has multi-path failover and does
	// not is worse off than one that knows it has none.
	ErrDiscoRequiresSalamanderV2 = errors.New("disco requires obfs.type salamander-v2")

	// ErrDiscoNoWireLength is what sending fails with before this session's
	// connection has carried a datagram disco could imitate. It should be
	// unreachable in operation -- the disco key does not exist until the QUIC
	// handshake completes, and completing it takes full-size datagrams -- and
	// it is an error rather than a guessed length precisely so that if it ever
	// does happen it is visible instead of being padded into a beacon.
	ErrDiscoNoWireLength = errors.New("disco has no wire length to imitate yet")

	ErrDiscoSeqExhausted = errors.New("disco sequence numbers exhausted")
)

// obfuscatedPacketConn is what extras/obfs's wrappers satisfy.
//
// It is asserted structurally rather than by importing that package, so that
// realm keeps not depending on obfs and a test can build the failing case
// without one. Nothing in the compiler ties the two halves together, so
// TestObfsConnsSatisfyTheDiscoGate does: it wraps a socket with every shipped
// obfuscator and checks both the interface and the name each one reports.
type obfuscatedPacketConn interface {
	ObfuscationName() string
}

// discoObfuscatorName is the one obfuscator disco runs over. It is the string
// extras/obfs's salamander v2 wrapper reports, and the test above is what keeps
// the two spellings the same.
const discoObfuscatorName = "salamander-v2"

// udpFeatures is the set of methods quic-go reaches through a PacketConn for
// its UDP optimizations (DF bit, path MTU detection, buffer sizing). The layers
// below us already proxy them down to the socket; if we did not proxy them on,
// wrapping the stack in a disco conn would silently turn them off.
type udpFeatures interface {
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

// DiscoPacketEvent is one authenticated, non-replayed disco packet.
type DiscoPacketEvent struct {
	// From is the address the datagram arrived from, which is not necessarily
	// the address QUIC is talking to. That difference is the entire value of the
	// control channel: a reply always goes back to From and never through QUIC's
	// remote address, so a path whose return direction has moved can still be
	// repaired over the path the packet actually took.
	From   netip.AddrPort
	At     time.Time
	Packet DiscoPacket
}

// DiscoStats are the counters that must not be merged into one. An
// authentication failure, a clock-skew rejection and a replay rejection are
// three different operational problems, and a single "disco errors" number
// diagnoses none of them.
type DiscoStats struct {
	// Delivered counts packets that passed every check.
	Delivered atomic.Uint64
	// AuthFail counts datagrams whose leading bytes matched a registered tag but
	// whose AEAD did not open. That is either a forgery or a real QUIC packet
	// colliding with a tag, which cannot be told apart, so the packet is handed
	// to QUIC either way and this counter is the only trace it leaves.
	AuthFail atomic.Uint64
	// BadVersion counts authenticated packets carrying an unknown version, which
	// is a peer running a protocol we do not have rather than an attack.
	BadVersion atomic.Uint64
	// ClockSkew counts packets rejected by the timestamp window, and
	// MaxSkewSeconds records the worst offset seen, so an operator gets a number
	// to check NTP against rather than a count of mysterious drops.
	ClockSkew      atomic.Uint64
	MaxSkewSeconds atomic.Int64
	// Replay counts packets whose sequence number had been seen or had fallen
	// out of the window.
	Replay atomic.Uint64
	// Malformed counts packets that authenticated but whose payload did not
	// parse. Since only the peer can produce one, a non-zero value here means
	// the two ends disagree about the format, not that someone is probing.
	Malformed atomic.Uint64
	// Dropped counts events discarded because a session's channel was full: a
	// reader that has stopped keeping up loses probes, and losing probes quietly
	// would look like a dead path.
	Dropped atomic.Uint64
}

type discoSession struct {
	id     string
	keys   *DiscoKeys
	events chan DiscoPacketEvent

	seq atomic.Uint32

	// wireLens is this session's padding target: the lengths its own QUIC
	// connection has recently sent. It is per session and not per socket
	// because on a server one socket carries every client, and one client's
	// path MTU has no business deciding another client's probe length -- the
	// probe goes out on the other client's path, where that length may not
	// even fit.
	wireLens discoWireLens

	// peer is the address whose outbound datagrams feed wireLens: this
	// connection's QUIC remote address. Read and written only under the conn's
	// peerMu.
	peer netip.AddrPort

	// tags are the entries this session currently owns in the conn's byTag
	// table. Keeping them here is what makes admission and removal cost one
	// session's worth of work instead of the whole table's; see addTagsLocked.
	// Written only under the conn's write lock.
	tags [][discoTagLen]byte

	mu     sync.Mutex
	window discoReplayWindow
}

// DiscoPacketConn routes disco packets to per-session event channels and passes
// everything else through to QUIC.
//
// It must wrap an obfuscated PacketConn; see ErrDiscoRequiresObfs.
type DiscoPacketConn struct {
	net.PacketConn

	// features is non-nil when the wrapped conn proxies the UDP-specific
	// methods, which every layer in the shipped stack does.
	features udpFeatures

	eventBuffer int
	stats       DiscoStats

	// now is the clock. It is a field so tests can step epochs and skew without
	// sleeping for two minutes.
	now func() time.Time

	// peerMu guards byPeer, and is separate from mu on purpose: byPeer is read
	// on the send path of every QUIC datagram, and mu is held for the whole
	// tag table while an epoch turns. Sharing one lock would stall every send
	// on the socket for the length of that rebuild.
	peerMu sync.RWMutex
	// byPeer routes an outbound datagram to the session whose connection sent
	// it, so that each session's padding target describes its own path. A
	// bucket rather than a single session because two QUIC connections can
	// share a remote address -- a reconnect from the same source port while the
	// old session is still being torn down -- and when they do they share the
	// path, so the same lengths describe both.
	byPeer map[netip.AddrPort][]*discoSession

	mu       sync.RWMutex
	sessions map[string]*discoSession
	// closed is set by Close, under the same lock as the session table because
	// it is read with it: the ticker exists while a session does, and a closed
	// conn has to look like one that never will again. See Close.
	closed bool
	// byTag is the demux index: one map lookup per inbound datagram, over every
	// session on the socket at once, with no trial decryption. A bucket holds
	// more than one session only if two sessions' tags collide, which is a
	// 2^-64 event handled rather than assumed away.
	byTag map[[discoTagLen]byte][]*discoSession
	epoch uint64

	tickerMu   sync.Mutex
	tickerStop chan struct{}
	tickerDone chan struct{}
}

// NewDiscoPacketConn wraps an obfuscated PacketConn with the disco demux.
func NewDiscoPacketConn(conn net.PacketConn, eventBuffer int) (*DiscoPacketConn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: conn is nil", ErrInvalidDiscoSession)
	}
	ob, ok := conn.(obfuscatedPacketConn)
	if !ok {
		return nil, ErrDiscoRequiresObfs
	}
	if name := ob.ObfuscationName(); name != discoObfuscatorName {
		return nil, fmt.Errorf("%w, not %s", ErrDiscoRequiresSalamanderV2, name)
	}
	if eventBuffer <= 0 {
		eventBuffer = defaultDiscoEventBuffer
	}
	features, _ := conn.(udpFeatures)
	return &DiscoPacketConn{
		PacketConn:  conn,
		features:    features,
		eventBuffer: eventBuffer,
		now:         time.Now,
		sessions:    make(map[string]*discoSession),
		byTag:       make(map[[discoTagLen]byte][]*discoSession),
		byPeer:      make(map[netip.AddrPort][]*discoSession),
	}, nil
}

// Stats returns the live disco counters. It is deliberately not called the same
// thing as obfs.StatsOf's target: wrapping an obfuscated conn in this one hides
// the obfuscator's own counters from a caller that looks for them on the
// outermost conn, so whoever assembles the stack has to keep a reference to the
// conn underneath.
func (c *DiscoPacketConn) Stats() *DiscoStats { return &c.stats }

func (c *DiscoPacketConn) SyscallConn() (syscall.RawConn, error) {
	if c.features == nil {
		return nil, errors.ErrUnsupported
	}
	return c.features.SyscallConn()
}

func (c *DiscoPacketConn) SetReadBuffer(bytes int) error {
	if c.features == nil {
		return errors.ErrUnsupported
	}
	return c.features.SetReadBuffer(bytes)
}

func (c *DiscoPacketConn) SetWriteBuffer(bytes int) error {
	if c.features == nil {
		return errors.ErrUnsupported
	}
	return c.features.SetWriteBuffer(bytes)
}

// AddDiscoSession installs one connection's key schedule and returns the channel
// its packets arrive on.
//
// Each session gets its own channel, so a session whose reader has gone away
// cannot swallow another session's packets. On a client there is one session; on
// a server there is one per QUIC connection, and the tag table is what routes a
// datagram to the right one.
//
// peer is the address this connection's QUIC datagrams go to. It is required
// rather than inferred because the disco layer has no other way to tell one
// connection's traffic from another's on a shared socket, and inferring it
// wrong is worse than not having it: the padding target would then be another
// client's, on another path. Whoever installs the session owns the QUIC
// connection and knows the address; when it moves, SetDiscoSessionPeer says so.
//
// A reconnect derives a new secret and so must install a new session: the keys
// are per-handshake, and anything remembered under the old ones -- the replay
// window above all -- has to go with them.
//
// After Close it fails with net.ErrClosed. A session admitted to a closed conn
// could receive nothing and send nothing, and it would put the conn's session
// count back above zero, which is what decides that the epoch ticker should be
// running.
// normaliseDiscoPeer puts a peer address into the form the datapath compares
// against. Datagrams reach WriteTo as a *net.UDPAddr and go through
// addrToAddrPort, which unmaps; a caller building an address the ordinary way
// -- net.ResolveUDPAddr, or anything that went near a dual-stack socket --
// hands over the v4-in-v6 form. Storing one form and looking up the other never
// matches, so the session is never credited with the datagrams sent to it and
// its probes are padded from nothing.
func normaliseDiscoPeer(peer netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
}

func (c *DiscoPacketConn) AddDiscoSession(id string, keys *DiscoKeys, peer netip.AddrPort) (<-chan DiscoPacketEvent, error) {
	peer = normaliseDiscoPeer(peer)
	if id == "" {
		return nil, fmt.Errorf("%w: id is required", ErrInvalidDiscoSession)
	}
	if keys == nil {
		return nil, fmt.Errorf("%w: keys are required", ErrInvalidDiscoSession)
	}
	if !peer.IsValid() {
		return nil, fmt.Errorf("%w: a peer address is required", ErrInvalidDiscoSession)
	}
	s := &discoSession{
		id:     id,
		keys:   keys,
		peer:   peer,
		events: make(chan DiscoPacketEvent, c.eventBuffer),
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if _, exists := c.sessions[id]; exists {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: duplicate id", ErrInvalidDiscoSession)
	}
	c.sessions[id] = s
	if err := c.addTagsLocked(s, c.now()); err != nil {
		delete(c.sessions, id)
		c.dropTagsLocked(s)
		c.mu.Unlock()
		return nil, err
	}
	// The peer index is filled while the session lock is still held, so that a
	// Close running beside this cannot clear that index in between the check
	// above and the insert and leave a dead conn holding a live entry. The
	// nesting is one-way: nothing takes peerMu and then mu.
	c.peerMu.Lock()
	c.byPeer[peer] = appendDiscoPeer(c.byPeer[peer], s)
	c.peerMu.Unlock()
	c.mu.Unlock()
	c.syncEpochTicker()
	return s.events, nil
}

// SetDiscoSessionPeer follows a connection whose path has moved, so that the
// session keeps sampling the lengths it is actually sending.
//
// A migration that is not reported here is not fatal: the window simply stops
// being refreshed and the target stays at the mode of the last burst the
// session was still sampling. That is the same degradation an idle connection
// gets, and it is deliberately a degradation rather than a silent switch to
// some other session's lengths.
func (c *DiscoPacketConn) SetDiscoSessionPeer(id string, peer netip.AddrPort) error {
	peer = normaliseDiscoPeer(peer)
	if !peer.IsValid() {
		return fmt.Errorf("%w: a peer address is required", ErrInvalidDiscoSession)
	}
	s := c.session(id)
	if s == nil {
		return ErrUnknownDiscoSession
	}
	c.peerMu.Lock()
	defer c.peerMu.Unlock()
	if s.peer == peer {
		return nil
	}
	c.dropPeerLocked(s)
	s.peer = peer
	c.byPeer[peer] = appendDiscoPeer(c.byPeer[peer], s)
	return nil
}

// RemoveDiscoSession forgets a session. The connection it belonged to is over,
// so its keys are dead: a new connection derives a new secret and cannot reuse
// anything here.
func (c *DiscoPacketConn) RemoveDiscoSession(id string) {
	c.mu.Lock()
	s, ok := c.sessions[id]
	if ok {
		delete(c.sessions, id)
		c.dropTagsLocked(s)
	}
	c.mu.Unlock()
	if ok {
		c.peerMu.Lock()
		c.dropPeerLocked(s)
		c.peerMu.Unlock()
	}
	c.syncEpochTicker()
}

// appendDiscoPeer keeps the same copy-on-write discipline the tag buckets keep;
// see appendDiscoBucket.
func appendDiscoPeer(bucket []*discoSession, s *discoSession) []*discoSession {
	next := make([]*discoSession, len(bucket)+1)
	copy(next, bucket)
	next[len(bucket)] = s
	return next
}

// dropPeerLocked removes one session from the peer index. Called with peerMu
// held for writing.
func (c *DiscoPacketConn) dropPeerLocked(s *discoSession) {
	bucket := c.byPeer[s.peer]
	next := make([]*discoSession, 0, len(bucket))
	for _, other := range bucket {
		if other != s {
			next = append(next, other)
		}
	}
	if len(next) == 0 {
		delete(c.byPeer, s.peer)
	} else {
		c.byPeer[s.peer] = next
	}
}

// WriteDisco seals p and sends it to addr, padded to a length this connection
// already sends at.
//
// It never consults or changes QUIC's remote address. That is what lets the
// control channel repair a data path: a reply goes to the address the packet
// that prompted it came from, which after a NAT rebinding is the only address
// that still works.
func (c *DiscoPacketConn) WriteDisco(id string, to netip.AddrPort, p DiscoPacket) error {
	s := c.session(id)
	if s == nil {
		return ErrUnknownDiscoSession
	}
	padTo := s.wireLens.mode()
	if padTo == 0 {
		return ErrDiscoNoWireLength
	}
	return c.writeDisco(s, to, p, padTo)
}

// WriteDiscoAt sends at a wire length the caller chooses.
//
// The length a control packet takes is what decides whether it is
// distinguishable, so measuring it needs the same control the sender has. It is
// exported for that, and for a caller that knows the length better than the
// sampler does; ordinary sending goes through WriteDisco.
func (c *DiscoPacketConn) WriteDiscoAt(id string, to netip.AddrPort, p DiscoPacket, padTo int) error {
	s := c.session(id)
	if s == nil {
		return ErrUnknownDiscoSession
	}
	return c.writeDisco(s, to, p, padTo)
}

func (c *DiscoPacketConn) writeDisco(s *discoSession, to netip.AddrPort, p DiscoPacket, padTo int) error {
	seq, err := s.nextSeq()
	if err != nil {
		return err
	}
	wire, err := EncodeDisco(p, s.keys, seq, c.now(), padTo)
	if err != nil {
		return err
	}
	// Written around the sampler on purpose: a disco packet that fed the
	// sampler would make the next one copy it, and the length distribution
	// would close over its own output instead of following the connection.
	_, err = c.PacketConn.WriteTo(wire, udpAddrFromAddrPort(to))
	return err
}

// nextSeq issues this session's next sequence number, or reports that it has
// none left.
//
// The ceiling is checked before the counter moves rather than after, and that
// is the whole point: an Add that has already overflowed cannot be undone, so a
// sender that tested the result would refuse for the sixteen numbers between
// the ceiling and 2^32 and then start again from zero -- measured, before this
// was a compare-and-swap: forty attempts from the ceiling produced sixteen
// refusals and twenty-four sends carrying sequence numbers 0 through 23. A far
// end's replay window would have rejected the ones it had seen and reopened
// itself for the rest.
func (s *discoSession) nextSeq() (uint32, error) {
	for {
		cur := s.seq.Load()
		if cur >= discoSeqCeiling-1 {
			return 0, ErrDiscoSeqExhausted
		}
		if s.seq.CompareAndSwap(cur, cur+1) {
			return cur + 1, nil
		}
	}
}

// PadToWireLen is the length a session's disco packets currently pad to, or
// zero when its connection has not sent anything a disco packet could imitate.
func (c *DiscoPacketConn) PadToWireLen(id string) int {
	s := c.session(id)
	if s == nil {
		return 0
	}
	return s.wireLens.mode()
}

// WriteTo records the length of everything QUIC sends against the session whose
// connection sent it, which is what that session's disco packets are then
// padded to match.
//
// Sampling here rather than below the obfuscator is what makes the number
// correct without knowing anything about the obfuscator: whatever it adds, it
// adds to a disco packet and to a data packet alike, so two payloads of equal
// length leave the socket as two datagrams of equal length.
//
// A datagram to an address no session has claimed is sent and not sampled. On a
// server that covers the packets QUIC sends to addresses it has no connection
// with -- version negotiation, retries, stateless resets -- and those are
// attacker-triggerable, so letting them create window state would be a memory
// an attacker could grow from off the path.
//
// The lookup is what the socket-wide window did not cost, so it was measured
// rather than assumed: 41 ns per datagram with a session registered against the
// address and 9 ns without, flat from one session to a thousand
// (BenchmarkDiscoPacketConnWriteTo, Apple M4). Most of the difference is the
// clock read the sample's timestamp needs, not the lookup. A real sendto is one
// to two microseconds, so this is a few percent of the send path, and it buys
// the guarantee that a probe takes its own connection's length.
func (c *DiscoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if to, ok := addrToAddrPort(addr); ok {
		c.peerMu.RLock()
		bucket := c.byPeer[to]
		if len(bucket) > 0 {
			now := c.now()
			for _, s := range bucket {
				s.wireLens.observe(len(p), now)
			}
		}
		c.peerMu.RUnlock()
	}
	return c.PacketConn.WriteTo(p, addr)
}

// discoWireLens is the window one session's padding target is computed over:
// the most common length among the last discoWireLenWindow datagrams its
// connection sent.
//
// The mode, and not the maximum. An earlier version of this took the largest
// length ever seen, and it was wrong twice over. It never fell, so one datagram
// at an old path's MTU pinned every later probe to a length the new path no
// longer produces -- measured: one 1439-byte send followed by 500 at 1200 left
// the target at 1439. And the largest length is not the one to aim at even when
// it is current: what a classifier learns is the set of lengths a deployment
// produces, so a length that is real but rare is still novel to it, while the
// mode is by construction the densest bucket in the flow. A control packet in
// that bucket is diluted by more traffic than any other choice offers, and an
// inter-arrival test over it sees the connection's cadence rather than the
// probe's.
//
// The mode also keeps the property the maximum was chosen for: the full-size
// datagram is the largest share of what a loaded connection sends, and more so
// once the lengths too short to imitate are dropped, so the mode *is* the
// full-size datagram, and a probe that long proves the candidate path carries a
// data packet.
//
// Reads and writes race by design, exactly as the punch sampler's do: the value
// is a length to imitate, and a slot that was overwritten mid-read holds a
// length this connection also sent. Making it exact would put a second lock on
// the send path of every QUIC packet.
type discoWireLens struct {
	lens [discoWireLenWindow]atomic.Uint32
	// at is when the slot beside it was written, in Unix nanoseconds. It is
	// stored after the length, so a torn read shows the slot as older than it
	// is and the freshness test errs towards calling it stale.
	at    [discoWireLenWindow]atomic.Int64
	count atomic.Uint64
}

func (w *discoWireLens) observe(n int, now time.Time) {
	// A length disco cannot be built at is no use as a target, and the floor is
	// what keeps the mode from becoming one. The runner-up length in a captured
	// flow is the ack-only datagram, a payload of under thirty bytes where the
	// empty envelope alone is discoMinWire, and it is 11% to 21% of the flow --
	// well behind the mode on every capture taken, so on those captures the
	// mode came out right either way. The floor is here so that it does not
	// depend on that ratio: a connection that goes quiet sends acks and little
	// else, and a target no disco packet can be built at is not a target.
	if n < discoMinWire || n > discoMaxWire {
		return
	}
	i := (w.count.Add(1) - 1) % discoWireLenWindow
	w.lens[i].Store(uint32(n))
	w.at[i].Store(now.UnixNano())
}

// mode returns the most common length among the datagrams this connection sent
// in the last discoWireLenMaxAge of its own activity, or zero when it has sent
// nothing a disco packet could imitate. Ties go to the longer length, because
// the longer probe is the one that also proves the candidate path carries a
// full-size data packet.
//
// The window is anchored to the newest sample rather than to the clock, and
// that is the answer to "what does a probe imitate when the connection has
// recently sent nothing worth imitating?": the last burst it did send, taken as
// a mode and not as a single packet. Anchoring to the clock instead would leave
// nothing at all to imitate on an idle connection, and refusing to send there
// is not available -- probing an idle connection is exactly when a Selector
// runs.
//
// What the anchor buys over taking the raw window is the mixed case, which is
// the one an idle connection produces: sixty datagrams at the old path's length
// and four at the new one still leave the raw mode naming the path the
// connection has left. It also bounds how far back a stale target can reach --
// to one burst, not to the whole window's history.
//
// A target that has gone stale is still a length this connection sent, so it is
// a length the deployment produces. That is what separates it from the failure
// a fixed target was rejected for: a hardcoded 1250 was caught at 100% by an
// offline-learned length whitelist because no data packet ever takes it, and
// staleness does not give a real length that property.
func (w *discoWireLens) mode() int {
	filled := int(min(w.count.Load(), uint64(discoWireLenWindow)))
	if filled == 0 {
		return 0
	}
	newest := int64(math.MinInt64)
	for i := range filled {
		if at := w.at[i].Load(); at > newest {
			newest = at
		}
	}
	since := newest - int64(discoWireLenMaxAge)

	var window [discoWireLenWindow]uint32
	n := 0
	for i := range filled {
		if w.at[i].Load() < since {
			continue
		}
		// Zero is only reachable against a concurrent first write to that slot.
		if v := w.lens[i].Load(); v != 0 {
			window[n] = v
			n++
		}
	}
	if n == 0 {
		return 0
	}
	sorted := window[:n]
	slices.Sort(sorted)
	best, bestRun := sorted[0], 1
	run := 1
	for i := 1; i < n; i++ {
		if sorted[i] == sorted[i-1] {
			run++
		} else {
			run = 1
		}
		// >= rather than >: the slice is ascending, so a tie takes the longer.
		if run >= bestRun {
			best, bestRun = sorted[i], run
		}
	}
	return int(best)
}

func (c *DiscoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if c.dispatch(p[:n], addr) {
			continue
		}
		return n, addr, nil
	}
}

// dispatch reports whether the datagram was consumed by the disco demux.
//
// Returning false hands the bytes to QUIC untouched, and it is what happens both
// when the leading tag is nobody's and when it is somebody's but the AEAD
// refuses. Those two cases cannot be told apart -- an eight-byte tag collides
// with a real QUIC packet once in 2^64 -- and dropping on collision would be a
// packet loss that occurs once in a thousand years per connection and can never
// be diagnosed when it does.
func (c *DiscoPacketConn) dispatch(packet []byte, addr net.Addr) bool {
	if len(packet) < discoMinWire || len(packet) > discoMaxWire {
		return false
	}
	var tag [discoTagLen]byte
	copy(tag[:], packet)

	c.mu.RLock()
	bucket := c.byTag[tag]
	c.mu.RUnlock()
	if len(bucket) == 0 {
		return false
	}
	from, ok := addrToAddrPort(addr)
	if !ok {
		return false
	}

	now := c.now()
	for _, s := range bucket {
		p, err := decodeDiscoBody(packet, s.keys, now)
		if err != nil {
			if errors.Is(err, ErrDiscoAuth) {
				// Not this session's. Another session in the bucket may still
				// own it; if none does, the loop falls through to QUIC.
				continue
			}
			c.countDecodeFailure(err)
			// It authenticated, so it is ours and QUIC must not see it.
			return true
		}
		// Everything above this point is stateless. The replay window is the
		// only thing a disco packet can advance, and it is advanced here, once,
		// after every check that could have rejected the packet has passed.
		if !s.accept(p.Header.Seq) {
			c.stats.Replay.Add(1)
			return true
		}
		c.stats.Delivered.Add(1)
		c.emit(s, DiscoPacketEvent{From: from, At: now, Packet: p})
		return true
	}
	c.stats.AuthFail.Add(1)
	return false
}

func (c *DiscoPacketConn) countDecodeFailure(err error) {
	var skew *DiscoSkewError
	switch {
	case errors.As(err, &skew):
		c.stats.ClockSkew.Add(1)
		secs := int64(skew.Skew / time.Second)
		if secs < 0 {
			secs = -secs
		}
		for {
			cur := c.stats.MaxSkewSeconds.Load()
			if secs <= cur || c.stats.MaxSkewSeconds.CompareAndSwap(cur, secs) {
				break
			}
		}
	case errors.Is(err, ErrDiscoBadVersion):
		c.stats.BadVersion.Add(1)
	default:
		c.stats.Malformed.Add(1)
	}
}

func (c *DiscoPacketConn) emit(s *discoSession, ev DiscoPacketEvent) {
	select {
	case s.events <- ev:
	default:
		c.stats.Dropped.Add(1)
	}
}

func (c *DiscoPacketConn) session(id string) *discoSession {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessions[id]
}

// addTagsLocked gives one session its entries in the tag table.
//
// It costs one session's three HKDF expansions, not the whole table's. That
// distinction is the difference between linear and quadratic admission, and on
// a server admission happens once per connecting client while holding the lock
// every inbound packet needs: rebuilding the table per arrival was measured at
// 123 ms to admit 500 sessions, 470 ms for 1000, 2.2 s for 2000 and 8.9 s for
// 4000 -- a clean N^2, and a client's connect latency at the top of it.
//
// The one case that still rebuilds is an epoch boundary crossed between two
// admissions. The new session's tags would otherwise be derived for a different
// epoch than every other session's, so the table has to catch up first; that
// happens at most once per epoch either way.
func (c *DiscoPacketConn) addTagsLocked(s *discoSession, now time.Time) error {
	if discoEpochOf(now) != c.epoch {
		return c.rebuildTagsLocked(now)
	}
	tags, err := s.keys.RecvTags(now)
	if err != nil {
		return err
	}
	s.tags = tags
	for _, t := range tags {
		c.byTag[t] = appendDiscoBucket(c.byTag[t], s)
	}
	return nil
}

// dropTagsLocked removes one session's entries, leaving every other session's
// alone. A bucket that empties is deleted so the table does not grow a tail of
// empty slices as connections come and go.
func (c *DiscoPacketConn) dropTagsLocked(s *discoSession) {
	for _, t := range s.tags {
		bucket := c.byTag[t]
		next := make([]*discoSession, 0, len(bucket))
		for _, other := range bucket {
			if other != s {
				next = append(next, other)
			}
		}
		if len(next) == 0 {
			delete(c.byTag, t)
		} else {
			c.byTag[t] = next
		}
	}
	s.tags = nil
}

// appendDiscoBucket copies rather than appending in place, and dropTagsLocked
// builds a fresh slice for the same reason: dispatch takes a bucket under the
// read lock and then walks it with the lock released, so a bucket that is
// already in the table must never be written to. The whole-table rebuild this
// replaced got that for free by publishing a new map; incremental updates have
// to say it. Buckets hold one session unless two sessions' tags collide, which
// is a 2^-64 event, so the copy is a one-element allocation per session per
// epoch.
//
// TestDiscoTagBucketsAreNeverWrittenInPlace pins it, and pins it as the rule
// rather than as its consequences: it watches the whole backing array of every
// bucket, including the slack capacity past the length, because that slack is
// where an in-place append lands and it is invisible to a reader that only
// looks at the values a bucket currently holds.
func appendDiscoBucket(bucket []*discoSession, s *discoSession) []*discoSession {
	next := make([]*discoSession, len(bucket)+1)
	copy(next, bucket)
	next[len(bucket)] = s
	return next
}

// rebuildTagsLocked recomputes the whole tag table for the epoch containing now.
//
// Every session registers the tags of the previous, current and next epoch, so
// the table has to be rebuilt as epochs pass and not only when sessions come and
// go. Rebuilding all of it is what keeps the previous epoch's tags from
// outliving their window.
//
// The table is built into a *fresh* map, and that is the whole mechanism rather
// than a style choice. Adding this epoch's tags to the map already there would
// never remove last epoch's, so a session would go on answering to every tag it
// had ever held: the +-120s the three-epoch window is meant to tolerate would
// widen without limit, and the table would grow by three entries per session per
// epoch for the life of the socket. TestDiscoTagTableDropsTheEpochsItLeaves
// pins both halves.
//
// A session whose tags cannot be derived is dropped from the table rather than
// left holding the previous epoch's: this can only fail the way HKDF fails,
// on a length it cannot produce, and these lengths are not that. Returning the
// error still matters at admission, where it is the caller's to see.
func (c *DiscoPacketConn) rebuildTagsLocked(now time.Time) error {
	byTag := make(map[[discoTagLen]byte][]*discoSession, len(c.sessions)*discoEpochsHeld)
	var firstErr error
	for _, s := range c.sessions {
		tags, err := s.keys.RecvTags(now)
		if err != nil {
			s.tags = nil
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s.tags = tags
		for _, t := range tags {
			byTag[t] = append(byTag[t], s)
		}
	}
	c.byTag = byTag
	c.epoch = discoEpochOf(now)
	return firstErr
}

// refreshTags rebuilds the tag table if the epoch has turned. It is what the
// ticker calls, and what a test calls instead of waiting two minutes.
func (c *DiscoPacketConn) refreshTags() {
	now := c.now()
	epoch := discoEpochOf(now)
	c.mu.RLock()
	current := c.epoch
	empty := len(c.sessions) == 0
	c.mu.RUnlock()
	if epoch == current || empty {
		return
	}
	c.mu.Lock()
	_ = c.rebuildTagsLocked(now)
	c.mu.Unlock()
}

// syncEpochTicker makes the ticker's existence match the session table: running
// while any session is registered, stopped when none is.
//
// The session count is read inside tickerMu rather than decided earlier and
// passed in, and that is the whole point. Deciding "there are no sessions left"
// under the session lock, releasing it and only then stopping the ticker leaves
// a window an admission can land in: the admission's own start finds the old
// ticker still alive and does nothing, the removal then stops it, and the
// session that remains never rotates its tags -- so two minutes later its
// peer's packets match no registered tag and go to QUIC as strangers. Reading
// the count here closes it, because every add and every remove calls this after
// its own change to the table, so whichever call takes tickerMu last sees the
// table as it finally is.
//
// That window is narrow enough that no test in this package reproduces it; see
// TestDiscoSessionsAdmitAndRemoveConcurrently for what was tried. The argument
// above is the evidence, not a measurement.
//
// A closed conn counts as having no sessions, which is what keeps Close final:
// the table is cleared and no later admission can refill it, so whatever calls
// this next stops the ticker or leaves it stopped.
//
// The count is not read while tickerMu is held *and* the session lock is held:
// stopping waits for the ticker goroutine, and that goroutine takes the session
// lock.
func (c *DiscoPacketConn) syncEpochTicker() {
	c.tickerMu.Lock()
	defer c.tickerMu.Unlock()
	c.mu.RLock()
	live := !c.closed && len(c.sessions) != 0
	c.mu.RUnlock()
	switch {
	case live && c.tickerStop == nil:
		c.startTickerLocked()
	case !live && c.tickerStop != nil:
		c.stopTickerLocked()
	}
}

func (c *DiscoPacketConn) startTickerLocked() {
	stop := make(chan struct{})
	done := make(chan struct{})
	c.tickerStop, c.tickerDone = stop, done
	go func() {
		defer close(done)
		t := time.NewTicker(discoEpochCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				c.refreshTags()
			}
		}
	}()
}

func (c *DiscoPacketConn) stopTickerLocked() {
	close(c.tickerStop)
	<-c.tickerDone
	c.tickerStop, c.tickerDone = nil, nil
}

// Close forgets every session and stops the epoch ticker before closing the
// socket.
//
// Dropping the sessions is not tidiness. The ticker's existence is decided by
// the session count, so a conn that closed with its table still populated would
// start a fresh ticker goroutine on a dead socket the next time a session was
// added or removed -- a goroutine rebuilding the tag table of a conn that can
// neither read nor write. Clearing the table and refusing later admissions are
// the two halves of closing that, and syncEpochTicker reads both.
//
// The socket is closed last, so that a datagram still in flight when Close ran
// goes on to QUIC rather than into the event channel of a session whose owner
// has already let go of it.
func (c *DiscoPacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.sessions = make(map[string]*discoSession)
	c.byTag = make(map[[discoTagLen]byte][]*discoSession)
	c.peerMu.Lock()
	c.byPeer = make(map[netip.AddrPort][]*discoSession)
	c.peerMu.Unlock()
	c.mu.Unlock()
	c.syncEpochTicker()
	return c.PacketConn.Close()
}

func (s *discoSession) accept(seq uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.window.accept(seq)
}

// discoReplayWindow is the sequence-number window from the design's receive
// state machine: a high-water mark and a 64-bit bitmap behind it.
//
// It is a window rather than "strictly greater than the last one" because disco
// sends a few packets a second and one reordering would otherwise be counted as
// a loss -- which is not a cosmetic difference, since the selector's decision to
// abandon a path is made out of exactly those counts.
type discoReplayWindow struct {
	high uint32
	bits uint64
	seen bool
}

func (w *discoReplayWindow) accept(seq uint32) bool {
	if seq == 0 {
		return false
	}
	if !w.seen {
		w.seen = true
		w.high = seq
		w.bits = 1
		return true
	}
	switch {
	case seq > w.high:
		if shift := seq - w.high; shift >= 64 {
			w.bits = 0
		} else {
			w.bits <<= shift
		}
		w.bits |= 1
		w.high = seq
		return true
	case w.high-seq >= 64:
		return false
	default:
		mask := uint64(1) << (w.high - seq)
		if w.bits&mask != 0 {
			return false
		}
		w.bits |= mask
		return true
	}
}
