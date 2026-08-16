package realm

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discoSocket stands in for the obfuscated conn a DiscoPacketConn wraps. It
// records what was written and delivers what a test injects, which is what the
// demux needs and all it needs -- the obfuscator itself adds the same overhead
// to a disco packet as to a data packet, so nothing the demux does depends on
// it being real.
type discoSocket struct {
	addr net.Addr
	in   chan discoDatagram
	// drop makes writes go nowhere, for benchmarks that must not measure the
	// recorder.
	drop bool

	mu     sync.Mutex
	writes []discoDatagram
	closed bool
	done   chan struct{}
}

type discoDatagram struct {
	data []byte
	addr net.Addr
}

func newDiscoSocket() *discoSocket {
	return &discoSocket{
		addr: udpAddrFromAddrPort(discoServerAddr),
		in:   make(chan discoDatagram, 64),
		done: make(chan struct{}),
	}
}

func (s *discoSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case d := <-s.in:
		return copy(p, d.data), d.addr, nil
	case <-s.done:
		return 0, nil, net.ErrClosed
	}
}

func (s *discoSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s.drop {
		// A benchmark would otherwise measure this slice growing rather than
		// the conn above it.
		return len(p), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, net.ErrClosed
	}
	s.writes = append(s.writes, discoDatagram{data: append([]byte(nil), p...), addr: addr})
	return len(p), nil
}

func (s *discoSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.done)
	}
	return nil
}

func (s *discoSocket) LocalAddr() net.Addr              { return s.addr }
func (s *discoSocket) SetDeadline(time.Time) error      { return nil }
func (s *discoSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *discoSocket) SetWriteDeadline(time.Time) error { return nil }

func (s *discoSocket) written() []discoDatagram {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]discoDatagram(nil), s.writes...)
}

func (s *discoSocket) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = nil
}

// deliver queues a datagram for the next ReadFrom, from a peer address that is
// deliberately not the socket's own: a disco reply goes back to where the
// packet came from, never to QUIC's remote address.
func (s *discoSocket) deliver(data []byte) {
	s.in <- discoDatagram{data: data, addr: udpAddrFromAddrPort(discoPeerAddr)}
}

// discoServerAddr is where a session's own QUIC datagrams go: the address a
// test registers a session against, and the one the socket's writes are
// addressed to, so that WriteTo feeds that session's length window.
//
// discoPeerAddr is deliberately a different address -- the one a disco packet
// arrives from and is answered at -- because a reply going back to where the
// packet came from rather than to QUIC's remote address is the whole reason the
// control channel can repair a path that has moved.
var (
	discoServerAddr = netip.MustParseAddrPort("192.0.2.1:4433")
	discoPeerAddr   = netip.MustParseAddrPort("192.0.2.2:4433")
)

// discoPeerN gives every session in a many-session test its own address, which
// is what a server sees: one QUIC connection per client, each on its own
// five-tuple. Sharing one address instead would measure the collision case,
// where a bucket grows and the copy that keeps it safe to read is O(bucket).
func discoPeerN(i int) netip.AddrPort {
	return netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}),
		uint16(1024+i%60000),
	)
}

// obfuscatedSocket is a discoSocket that reports an obfuscator, which is the
// only kind NewDiscoPacketConn accepts.
type obfuscatedSocket struct {
	*discoSocket
	name string
}

func (s obfuscatedSocket) ObfuscationName() string { return s.name }

// udpObfuscatedSocket additionally carries the UDP methods quic-go reaches
// through a PacketConn for.
type udpObfuscatedSocket struct {
	obfuscatedSocket
	readBuffer, writeBuffer int
}

func (s *udpObfuscatedSocket) SyscallConn() (syscall.RawConn, error) { return nil, nil }
func (s *udpObfuscatedSocket) SetReadBuffer(n int) error             { s.readBuffer = n; return nil }
func (s *udpObfuscatedSocket) SetWriteBuffer(n int) error            { s.writeBuffer = n; return nil }

// newDiscoConn builds a conn over a salamander v2 socket with the two sessions
// of one connection: the client's, which the conn holds, and the server's,
// which a test uses to forge the packets arriving at it.
func newDiscoConn(tb testing.TB) (*discoSocket, *DiscoPacketConn) {
	tb.Helper()
	sock := newDiscoSocket()
	conn, err := NewDiscoPacketConn(obfuscatedSocket{sock, discoObfuscatorName}, 4)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = conn.Close() })
	return sock, conn
}

// newDiscoConnWithSession is newDiscoConn with session "c" already registered
// against the address the socket writes to, which is what the padding target
// now needs: the window belongs to a session, so a test that never registers
// one has nowhere for a length to land.
func newDiscoConnWithSession(tb testing.TB) (*discoSocket, *DiscoPacketConn) {
	tb.Helper()
	sock, conn := newDiscoConn(tb)
	client, _ := discoTestKeys(tb)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(tb, err)
	return sock, conn
}

// fixClock pins the conn's clock so epochs and skew are stepped rather than
// waited for.
func fixClock(c *DiscoPacketConn, at *time.Time) {
	c.now = func() time.Time { return *at }
}

// NewDiscoPacketConn is the startup gate. It has to refuse rather than degrade:
// the whole envelope is safe only because something underneath turns it into
// uniform random bytes of a length the flow already produces, and only
// salamander v2's background was ever captured. Gecko is not just unmeasured --
// it pads to a random size in a range, so there is no modal length to copy.
func TestNewDiscoPacketConnRequiresSalamanderV2(t *testing.T) {
	if _, err := NewDiscoPacketConn(nil, 4); !assert.ErrorIs(t, err, ErrInvalidDiscoSession) {
		return
	}

	// A bare socket carries no ObfuscationName at all.
	_, err := NewDiscoPacketConn(newDiscoSocket(), 4)
	assert.ErrorIs(t, err, ErrDiscoRequiresObfs)

	for _, name := range []string{"salamander", "gecko", "plain"} {
		_, err := NewDiscoPacketConn(obfuscatedSocket{newDiscoSocket(), name}, 4)
		assert.ErrorIsf(t, err, ErrDiscoRequiresSalamanderV2,
			"obfuscator %q was admitted; nothing has measured what disco looks like under it", name)
		assert.Containsf(t, err.Error(), name, "the refusal does not say which obfuscator was configured")
	}

	conn, err := NewDiscoPacketConn(obfuscatedSocket{newDiscoSocket(), "salamander-v2"}, 4)
	require.NoError(t, err)
	assert.NoError(t, conn.Close())
}

func TestNewDiscoPacketConnDefaultsTheEventBuffer(t *testing.T) {
	conn, err := NewDiscoPacketConn(obfuscatedSocket{newDiscoSocket(), discoObfuscatorName}, 0)
	require.NoError(t, err)
	defer conn.Close()
	assert.Equal(t, defaultDiscoEventBuffer, conn.eventBuffer)
}

// The padding target is the modal recent length, not the largest one ever seen.
//
// The maximum was wrong in both directions. It never falls, so a single
// datagram at an old path's MTU pins every later probe to a length the new path
// does not produce; and a maximum is a length the flow may produce rarely,
// while a classifier's whitelist is built out of the lengths a deployment
// actually produces. The mode is the densest bucket by construction.
func TestDiscoPadsToTheModeNotTheMaximum(t *testing.T) {
	sock, conn := newDiscoConnWithSession(t)

	// The measured failure, verbatim: one full-size datagram on the old path,
	// then a long run at the new one.
	_, err := conn.WriteTo(make([]byte, 1439), sock.addr)
	require.NoError(t, err)
	for range 500 {
		_, err := conn.WriteTo(make([]byte, 1200), sock.addr)
		require.NoError(t, err)
	}
	assert.Equal(t, 1200, conn.PadToWireLen("c"),
		"the target did not follow the path down; it is tracking the maximum")

	// And within one window: a length that occurs once does not win over one
	// that occurs sixty-three times just by being longer.
	sock2, conn2 := newDiscoConnWithSession(t)
	for range discoWireLenWindow - 1 {
		_, err := conn2.WriteTo(make([]byte, 1200), sock2.addr)
		require.NoError(t, err)
	}
	_, err = conn2.WriteTo(make([]byte, discoMaxWire), sock2.addr)
	require.NoError(t, err)
	assert.Equal(t, 1200, conn2.PadToWireLen("c"), "a length seen once became the target")

	// A tie goes to the longer length: both are equally dense, and the longer
	// probe is the one that also proves the candidate path carries a full-size
	// data packet.
	sock3, conn3 := newDiscoConnWithSession(t)
	for range discoWireLenWindow / 2 {
		_, err := conn3.WriteTo(make([]byte, 1200), sock3.addr)
		require.NoError(t, err)
		_, err = conn3.WriteTo(make([]byte, 1439), sock3.addr)
		require.NoError(t, err)
	}
	assert.Equal(t, 1439, conn3.PadToWireLen("c"), "a tie did not go to the longer length")
}

// The window is short so that it describes what the connection is sending now.
// A target that took the whole history would average over a path MTU change
// instead of following it.
func TestDiscoPadTargetForgetsTheOldPath(t *testing.T) {
	sock, conn := newDiscoConnWithSession(t)
	for range discoWireLenWindow {
		_, err := conn.WriteTo(make([]byte, 1439), sock.addr)
		require.NoError(t, err)
	}
	require.Equal(t, 1439, conn.PadToWireLen("c"))

	for range discoWireLenWindow {
		_, err := conn.WriteTo(make([]byte, 1100), sock.addr)
		require.NoError(t, err)
	}
	assert.Equal(t, 1100, conn.PadToWireLen("c"),
		"a full window of the new path's length did not displace the old one")
}

// How long the window is decides one thing and only one: how much of a new path
// it takes to move the target. A bare majority of the window does it and a
// minority does not, which is the sense in which the window is "short enough to
// follow a path MTU change and long enough not to chase a stray length".
//
// The counts are literal because counts expressed in discoWireLenWindow hold
// for every value of it. These do not: at a window of 8 the minority case moves
// the target, and at 128 the majority case fails to, so the pair pins the
// window to between 62 and 65 samples. The prefill is far longer than any of
// those, so what the cases measure is the window and not the prefill.
func TestDiscoWireLenWindowTakesAMajorityToMove(t *testing.T) {
	for _, tc := range []struct {
		name      string
		onNewPath int
		want      int
	}{
		{"a minority of the window leaves the target alone", 31, 1439},
		{"a majority of it moves the target", 33, 1200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, conn := newDiscoConnWithSession(t)
			for range 256 {
				_, err := conn.WriteTo(make([]byte, 1439), sock.addr)
				require.NoError(t, err)
			}
			require.Equal(t, 1439, conn.PadToWireLen("c"))

			for range tc.onNewPath {
				_, err := conn.WriteTo(make([]byte, 1200), sock.addr)
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, conn.PadToWireLen("c"),
				"%d datagrams on the new path", tc.onNewPath)
		})
	}
}

// A window full of old lengths must not out-vote the few a resumed connection
// has just sent. This is the idle case, and the one a Selector meets first: it
// probes a connection precisely when the application has stopped feeding it, so
// without a clock on the samples the target ages into whatever the flow looked
// like when it was last busy -- here, sixty datagrams at a path MTU the
// connection has already left.
func TestDiscoPadTargetPrefersFreshSamples(t *testing.T) {
	sock, conn := newDiscoConnWithSession(t)
	at := time.Unix(1_700_000_000, 0)
	fixClock(conn, &at)

	for range discoWireLenWindow - 4 {
		_, err := conn.WriteTo(make([]byte, 1439), sock.addr)
		require.NoError(t, err)
	}
	require.Equal(t, 1439, conn.PadToWireLen("c"))

	// An hour idle, then the connection resumes on a path with a smaller MTU.
	at = at.Add(time.Hour)
	for range 4 {
		_, err := conn.WriteTo(make([]byte, 1339), sock.addr)
		require.NoError(t, err)
	}
	assert.Equal(t, 1339, conn.PadToWireLen("c"),
		"the target was decided by samples an hour older than the path")

	// Another hour with nothing newer, and the target is still that burst
	// rather than nothing: the window is anchored to the connection's own last
	// activity and not to the clock, because refusing here would leave a
	// Selector unable to probe an idle connection, which is when it runs.
	at = at.Add(time.Hour)
	assert.Equal(t, 1339, conn.PadToWireLen("c"),
		"an idle connection stopped having a length to imitate")
}

// Lengths a disco packet cannot take are not targets. The floor is what makes
// the mode mean anything: ack-only datagrams are the second most common thing a
// QUIC connection sends and are far shorter than the envelope, so without the
// floor the mode would be a length no probe could be built at.
func TestDiscoWireLenWindowSkipsLengthsDiscoCannotTake(t *testing.T) {
	sock, conn := newDiscoConnWithSession(t)

	_, err := conn.WriteTo(make([]byte, discoMinWire-1), sock.addr)
	require.NoError(t, err)
	_, err = conn.WriteTo(make([]byte, discoMaxWire+1), sock.addr)
	require.NoError(t, err)
	assert.Zero(t, conn.PadToWireLen("c"), "a length disco cannot be built at became the target")

	// A quiet connection, where the acks outnumber the full-size datagrams two
	// to one. The full-size length must still be the target, because the other
	// one is not a length a disco packet can be built at.
	for range 10 {
		for range 2 {
			_, err := conn.WriteTo(make([]byte, 30), sock.addr)
			require.NoError(t, err)
		}
		_, err := conn.WriteTo(make([]byte, 1439), sock.addr)
		require.NoError(t, err)
	}
	assert.Equal(t, 1439, conn.PadToWireLen("c"))
}

// One socket, two clients: each session's probe must take its own connection's
// length. Measured on the branch this replaced, where the window belonged to
// the socket: sixty datagrams at 1439 for one client and four at 1339 for the
// other left both sessions padding to 1439 -- and the second session's probe
// goes out on the second client's path, where 1439 may not fit.
func TestDiscoPadTargetIsPerSessionNotPerSocket(t *testing.T) {
	sock, conn := newDiscoConn(t)
	busyKeys, _ := discoTestKeys(t)
	quietSecret := append([]byte(nil), discoSecret...)
	quietSecret[0] ^= 0xff
	quietKeys, err := NewDiscoKeys(quietSecret, false)
	require.NoError(t, err)

	busyPeer := netip.MustParseAddrPort("198.51.100.7:9001")
	quietPeer := netip.MustParseAddrPort("198.51.100.8:9002")
	_, err = conn.AddDiscoSession("busy", busyKeys, busyPeer)
	require.NoError(t, err)
	_, err = conn.AddDiscoSession("quiet", quietKeys, quietPeer)
	require.NoError(t, err)

	for range 60 {
		_, err := conn.WriteTo(make([]byte, 1439), udpAddrFromAddrPort(busyPeer))
		require.NoError(t, err)
	}
	for range 4 {
		_, err := conn.WriteTo(make([]byte, 1339), udpAddrFromAddrPort(quietPeer))
		require.NoError(t, err)
	}

	assert.Equal(t, 1439, conn.PadToWireLen("busy"))
	assert.Equal(t, 1339, conn.PadToWireLen("quiet"),
		"one client's path MTU decided another client's probe length")

	sock.reset()
	require.NoError(t, conn.WriteDisco("quiet", discoPeerAddr, discoTestPackets()[0]))
	sent := sock.written()
	require.Len(t, sent, 1)
	assert.Len(t, sent[0].data, 1339, "the probe took a length from another client's connection")
}

// A datagram to an address no session claims is sent and not sampled. On a
// server that is version negotiation, retries and stateless resets, all of them
// triggerable by anyone who can send a packet, so letting them create window
// state would be a memory an attacker grows from off the path.
func TestDiscoSamplesOnlyItsSessionsPaths(t *testing.T) {
	sock, conn := newDiscoConnWithSession(t)

	stranger := udpAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.9:1234"))
	for range discoWireLenWindow {
		_, err := conn.WriteTo(make([]byte, 1439), stranger)
		require.NoError(t, err)
	}
	assert.Zero(t, conn.PadToWireLen("c"), "a datagram to a stranger fed a session's window")

	conn.peerMu.RLock()
	peers := len(conn.byPeer)
	conn.peerMu.RUnlock()
	assert.Equal(t, 1, peers, "sending to a stranger created an index entry")

	_, err := conn.WriteTo(make([]byte, 1439), sock.addr)
	require.NoError(t, err)
	assert.Equal(t, 1439, conn.PadToWireLen("c"))
}

// A connection whose path has moved keeps sampling, and stops sampling the path
// it left.
func TestSetDiscoSessionPeerFollowsTheConnection(t *testing.T) {
	_, conn := newDiscoConnWithSession(t)
	moved := netip.MustParseAddrPort("198.51.100.30:5555")

	for range discoWireLenWindow {
		_, err := conn.WriteTo(make([]byte, 1439), udpAddrFromAddrPort(discoServerAddr))
		require.NoError(t, err)
	}
	require.NoError(t, conn.SetDiscoSessionPeer("c", moved))

	for range discoWireLenWindow {
		_, err := conn.WriteTo(make([]byte, 1200), udpAddrFromAddrPort(moved))
		require.NoError(t, err)
	}
	assert.Equal(t, 1200, conn.PadToWireLen("c"))

	for range discoWireLenWindow {
		_, err := conn.WriteTo(make([]byte, 1439), udpAddrFromAddrPort(discoServerAddr))
		require.NoError(t, err)
	}
	assert.Equal(t, 1200, conn.PadToWireLen("c"),
		"the session went on sampling the path it had left")

	assert.ErrorIs(t, conn.SetDiscoSessionPeer("nobody", moved), ErrUnknownDiscoSession)
	assert.ErrorIs(t, conn.SetDiscoSessionPeer("c", netip.AddrPort{}), ErrInvalidDiscoSession)
}

// The sampler must not learn from disco packets. If it did, the first probe's
// length would become the target the next one copies and the distribution would
// close over its own output instead of following the connection.
func TestDiscoPacketsAreNotSamples(t *testing.T) {
	sock, conn := newDiscoConn(t)
	client, _ := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	// A target the connection really has, so that the assertion below is a
	// length holding against the probes rather than a zero that was already
	// true before any of them were sent.
	for range 256 {
		_, err := conn.WriteTo(make([]byte, 1439), sock.addr)
		require.NoError(t, err)
	}
	require.Equal(t, 1439, conn.PadToWireLen("c"))

	// The probes are aimed at the session's own peer, which is the only address
	// the sampler credits. Aimed anywhere else they could not be sampled even
	// through the public WriteTo, and this test would go on passing with the
	// bypass in writeDisco removed -- which is the one regression it exists to
	// catch, and which it did not catch: routing writeDisco through c.WriteTo
	// left the whole package green.
	sock.reset()
	for range 256 {
		require.NoError(t, conn.WriteDiscoAt("c", discoServerAddr, discoTestPackets()[0], 900))
	}
	require.Len(t, sock.written(), 256)
	assert.Equal(t, 1439, conn.PadToWireLen("c"), "disco packets fed the length window")
}

// A probe goes to the address it is aimed at, at exactly the modal length. The
// address matters as much as the length: replying to where the packet came from
// rather than to QUIC's remote address is the whole reason the control channel
// can repair a path that has moved.
func TestWriteDiscoUsesTheModeAndTheGivenAddress(t *testing.T) {
	sock, conn := newDiscoConn(t)
	client, server := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	for range discoWireLenWindow {
		_, err := conn.WriteTo(make([]byte, 1439), sock.addr)
		require.NoError(t, err)
	}
	sock.reset()
	require.NoError(t, conn.WriteDisco("c", discoPeerAddr, discoTestPackets()[0]))

	sent := sock.written()
	require.Len(t, sent, 1)
	assert.Len(t, sent[0].data, 1439, "the probe did not take the modal length")
	assert.Equal(t, udpAddrFromAddrPort(discoPeerAddr).String(), sent[0].addr.String())

	got, err := DecodeDisco(sent[0].data, server, time.Now())
	require.NoError(t, err)
	assert.Equal(t, DiscoProbeType, got.Header.Type)
	assert.Equal(t, uint32(1), got.Header.Seq, "the first packet of a session is not seq 1")
}

// Sending before the socket has carried anything is an error, not a guess. It
// should be unreachable -- the disco keys come from the TLS exporter, and
// completing that handshake takes full-size datagrams -- and if it ever does
// happen it has to be visible rather than padded into a beacon.
func TestWriteDiscoRefusesWithoutALengthToImitate(t *testing.T) {
	_, conn := newDiscoConn(t)
	client, _ := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)
	assert.ErrorIs(t, conn.WriteDisco("c", discoPeerAddr, discoTestPackets()[0]), ErrDiscoNoWireLength)
}

func TestWriteDiscoRefusesAnUnknownSession(t *testing.T) {
	_, conn := newDiscoConn(t)
	assert.ErrorIs(t, conn.WriteDiscoAt("nobody", discoPeerAddr, discoTestPackets()[0], 900),
		ErrUnknownDiscoSession)
}

// A sender stops rather than wrapping. A wrapped sequence number would silently
// reopen the replay window on the far end.
//
// The assertion is that it stays stopped, and that is not pedantry: a version
// of this that incremented first and tested the result refused for the sixteen
// numbers between the ceiling and 2^32 and then sent again from zero. Sending
// past the point of refusal is what the far end cannot survive, so the test
// keeps asking long after the first refusal, and checks the packets rather than
// only the errors -- a sequence number the far end would reject is one this
// side must never have put on the wire.
func TestWriteDiscoStopsAtTheSequenceCeiling(t *testing.T) {
	sock, conn := newDiscoConn(t)
	client, server := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)
	s := conn.session("c")
	require.NotNil(t, s)

	s.seq.Store(discoSeqCeiling - 2)
	assert.NoError(t, conn.WriteDiscoAt("c", discoPeerAddr, discoTestPackets()[0], 900))
	sock.reset()

	now := time.Now()
	for range 64 {
		assert.ErrorIs(t, conn.WriteDiscoAt("c", discoPeerAddr, discoTestPackets()[0], 900),
			ErrDiscoSeqExhausted)
	}
	assert.Empty(t, sock.written(), "the sender kept sending after its sequence numbers ran out")

	// The counter itself must not have moved past the ceiling either: a
	// counter parked at 2^32-1 is one send away from starting over.
	assert.Less(t, s.seq.Load(), uint32(discoSeqCeiling),
		"the sequence counter advanced past the ceiling and can still wrap")

	// And the last packet that did go out carries a sequence number the far end
	// accepts, rather than the zero DecodeDisco refuses.
	s.seq.Store(discoSeqCeiling - 2)
	require.NoError(t, conn.WriteDiscoAt("c", discoPeerAddr, discoTestPackets()[0], 900))
	sent := sock.written()
	require.Len(t, sent, 1)
	got, err := DecodeDisco(sent[0].data, server, now)
	require.NoError(t, err)
	assert.Equal(t, uint32(discoSeqCeiling-1), got.Header.Seq)
}

func TestAddDiscoSessionValidatesItsArguments(t *testing.T) {
	_, conn := newDiscoConn(t)
	client, _ := discoTestKeys(t)

	_, err := conn.AddDiscoSession("", client, discoServerAddr)
	assert.ErrorIs(t, err, ErrInvalidDiscoSession)
	_, err = conn.AddDiscoSession("c", nil, discoServerAddr)
	assert.ErrorIs(t, err, ErrInvalidDiscoSession)
	// A session with no peer address would sample nothing and pad to nothing,
	// which is a configuration mistake that has to be loud rather than silent.
	_, err = conn.AddDiscoSession("c", client, netip.AddrPort{})
	assert.ErrorIs(t, err, ErrInvalidDiscoSession, "a session with no peer address was admitted")

	_, err = conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)
	_, err = conn.AddDiscoSession("c", client, discoServerAddr)
	assert.ErrorIs(t, err, ErrInvalidDiscoSession, "a duplicate id was admitted")
}

// discoReadResult is what a background ReadFrom saw, so a test can assert both
// that a disco packet never reached QUIC and that a data packet did.
type discoReadResult struct {
	data []byte
	err  error
}

func readInBackground(conn *DiscoPacketConn) <-chan discoReadResult {
	out := make(chan discoReadResult, 1)
	go func() {
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFrom(buf)
		out <- discoReadResult{data: append([]byte(nil), buf[:n]...), err: err}
	}()
	return out
}

func requireRead(t *testing.T, ch <-chan discoReadResult) discoReadResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom never returned")
		return discoReadResult{}
	}
}

func requireEvent(t *testing.T, ch <-chan DiscoPacketEvent) DiscoPacketEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no disco event arrived")
		return DiscoPacketEvent{}
	}
}

// The demux takes disco packets out of the stream and hands everything else to
// QUIC untouched, and it reports the address the datagram actually came from
// rather than anything QUIC knows.
func TestDiscoDemuxDeliversAndKeepsItFromQUIC(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, server := discoTestKeys(t)
	events, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	// The peer is the server, so it seals with the server schedule.
	wire, err := EncodeDisco(discoTestPackets()[1], server, 7, now, 900)
	require.NoError(t, err)

	read := readInBackground(conn)
	sock.deliver(wire)
	sock.deliver([]byte("not a disco packet"))

	ev := requireEvent(t, events)
	assert.Equal(t, DiscoPongType, ev.Packet.Header.Type)
	assert.Equal(t, uint32(7), ev.Packet.Header.Seq)
	assert.Equal(t, discoPeerAddr, ev.From)
	assert.True(t, ev.At.Equal(now))

	got := requireRead(t, read)
	require.NoError(t, got.err)
	assert.Equal(t, []byte("not a disco packet"), got.data,
		"a disco packet reached QUIC, or a data packet did not")
	assert.Equal(t, uint64(1), conn.Stats().Delivered.Load())
}

// A datagram whose leading bytes are nobody's tag is not disco and never gets
// looked at twice. So is one that is too short or too long to be disco.
func TestDiscoDemuxPassesStrangersToQUIC(t *testing.T) {
	sock, conn := newDiscoConn(t)
	client, _ := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	for _, packet := range [][]byte{
		make([]byte, discoMinWire-1),
		make([]byte, discoMaxWire+1),
		append([]byte("no tag of ours"), make([]byte, 900)...),
	} {
		read := readInBackground(conn)
		sock.deliver(packet)
		got := requireRead(t, read)
		require.NoError(t, got.err)
		assert.Len(t, got.data, len(packet))
	}
	assert.Zero(t, conn.Stats().Delivered.Load())
	assert.Zero(t, conn.Stats().AuthFail.Load())
}

// A tag that matches but an AEAD that does not is either a forgery or a real
// QUIC packet colliding with a registered tag, and the two cannot be told
// apart. Dropping it would be a packet loss nobody could ever diagnose, so it
// goes to QUIC and the counter is the only trace it leaves.
func TestDiscoDemuxHandsAuthFailuresToQUIC(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, server := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	wire, err := EncodeDisco(discoTestPackets()[0], server, 1, now, 900)
	require.NoError(t, err)
	wire[len(wire)-1] ^= 0x01

	read := readInBackground(conn)
	sock.deliver(wire)
	got := requireRead(t, read)
	require.NoError(t, got.err)
	assert.Len(t, got.data, 900)
	assert.Equal(t, uint64(1), conn.Stats().AuthFail.Load())
	assert.Zero(t, conn.Stats().Delivered.Load())
}

// The counters must stay apart. An authentication failure, a clock-skew
// rejection and a replay are three different operational problems, and one
// "disco errors" number diagnoses none of them.
func TestDiscoStatsSeparateTheFailures(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, server := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	// Everything below authenticates, so the demux consumes it and QUIC never
	// sees it. One trailing data packet gives ReadFrom something to return.
	skewed, err := EncodeDisco(discoTestPackets()[0], server, 1, now.Add(-discoMaxSkew-90*time.Second), 900)
	require.NoError(t, err)
	badVersion := forgeDiscoWire(t, server, func(plain []byte) { plain[0] = 0x03 })
	malformed := forgeDiscoWire(t, server, func(plain []byte) { plain[1] = 0x7f })

	read := readInBackground(conn)
	sock.deliver(skewed)
	sock.deliver(badVersion)
	sock.deliver(malformed)
	sock.deliver([]byte("data packet"))
	require.NoError(t, requireRead(t, read).err)

	st := conn.Stats()
	assert.Equal(t, uint64(1), st.ClockSkew.Load())
	assert.Equal(t, int64(120), st.MaxSkewSeconds.Load(), "the operator gets no number to check NTP against")
	assert.Equal(t, uint64(1), st.BadVersion.Load())
	assert.Equal(t, uint64(1), st.Malformed.Load())
	assert.Zero(t, st.Delivered.Load())
}

// A reader that has stopped keeping up loses probes, and losing them quietly
// would look to the selector like a dead path.
func TestDiscoCountsEventsDroppedOnAFullChannel(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, server := discoTestKeys(t)
	events, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	read := readInBackground(conn)
	for i := range conn.eventBuffer + 3 {
		wire, err := EncodeDisco(discoTestPackets()[0], server, uint32(i+1), now, 900)
		require.NoError(t, err)
		sock.deliver(wire)
	}
	sock.deliver([]byte("data packet"))
	require.NoError(t, requireRead(t, read).err)

	assert.Len(t, events, conn.eventBuffer)
	assert.Equal(t, uint64(3), conn.Stats().Dropped.Load())
	assert.Equal(t, uint64(conn.eventBuffer+3), conn.Stats().Delivered.Load(),
		"a dropped event is still a delivered packet; the two counters answer different questions")
}

// A repeated sequence number is consumed and counted, never handed to QUIC and
// never delivered twice: a replayed BIND is a path claim replayed.
func TestDiscoDemuxRejectsAReplay(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, server := discoTestKeys(t)
	events, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	wire, err := EncodeDisco(discoTestPackets()[0], server, 4, now, 900)
	require.NoError(t, err)

	read := readInBackground(conn)
	sock.deliver(append([]byte(nil), wire...))
	sock.deliver(append([]byte(nil), wire...))
	sock.deliver([]byte("data packet"))
	require.NoError(t, requireRead(t, read).err)

	requireEvent(t, events)
	assert.Empty(t, events, "a replayed packet was delivered twice")
	assert.Equal(t, uint64(1), conn.Stats().Replay.Load())
	assert.Equal(t, uint64(1), conn.Stats().Delivered.Load())
}

// Each session gets its own channel, so a session whose reader has gone away
// cannot swallow another session's packets. On a server there is one session
// per QUIC connection and the tag table is what routes a datagram to the right
// one.
func TestDiscoSessionsDoNotShareChannels(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	clientA, _ := discoTestKeys(t)
	otherSecret := append([]byte(nil), discoSecret...)
	otherSecret[0] ^= 0xff
	clientB, err := NewDiscoKeys(otherSecret, false)
	require.NoError(t, err)
	serverB, err := NewDiscoKeys(otherSecret, true)
	require.NoError(t, err)

	eventsA, err := conn.AddDiscoSession("a", clientA, discoServerAddr)
	require.NoError(t, err)
	eventsB, err := conn.AddDiscoSession("b", clientB, discoServerAddr)
	require.NoError(t, err)

	wire, err := EncodeDisco(discoTestPackets()[0], serverB, 1, now, 900)
	require.NoError(t, err)
	read := readInBackground(conn)
	sock.deliver(wire)
	sock.deliver([]byte("data packet"))
	require.NoError(t, requireRead(t, read).err)

	requireEvent(t, eventsB)
	assert.Empty(t, eventsA, "one connection's probe was delivered to another's channel")
}

// A removed session's packets stop being ours. The connection it belonged to is
// over, so its keys are dead, and anything still arriving under them belongs to
// QUIC.
func TestRemoveDiscoSessionStopsDelivery(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, server := discoTestKeys(t)
	events, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)
	conn.RemoveDiscoSession("c")

	wire, err := EncodeDisco(discoTestPackets()[0], server, 1, now, 900)
	require.NoError(t, err)
	read := readInBackground(conn)
	sock.deliver(wire)
	got := requireRead(t, read)
	require.NoError(t, got.err)
	assert.Len(t, got.data, 900, "a removed session's packet was still consumed")
	assert.Empty(t, events)
	assert.Zero(t, conn.Stats().Delivered.Load())
}

// Removing one session must leave every other session's tags in place. The
// incremental table is what makes admission linear, and the failure it invites
// is exactly this: a removal that takes a neighbour's entries with it.
func TestRemoveDiscoSessionLeavesTheOthersRoutable(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	keys := make([]*DiscoKeys, 8)
	peers := make([]*DiscoKeys, 8)
	for i := range keys {
		secret := append([]byte(nil), discoSecret...)
		secret[0] = byte(i)
		var err error
		keys[i], err = NewDiscoKeys(secret, false)
		require.NoError(t, err)
		peers[i], err = NewDiscoKeys(secret, true)
		require.NoError(t, err)
	}
	channels := make([]<-chan DiscoPacketEvent, len(keys))
	for i, k := range keys {
		var err error
		channels[i], err = conn.AddDiscoSession(string(rune('a'+i)), k, discoServerAddr)
		require.NoError(t, err)
	}
	for i := 0; i < len(keys); i += 2 {
		conn.RemoveDiscoSession(string(rune('a' + i)))
	}

	read := readInBackground(conn)
	for i := 1; i < len(keys); i += 2 {
		wire, err := EncodeDisco(discoTestPackets()[0], peers[i], 1, now, 900)
		require.NoError(t, err)
		sock.deliver(wire)
	}
	sock.deliver([]byte("data packet"))
	require.NoError(t, requireRead(t, read).err)

	for i := 1; i < len(keys); i += 2 {
		assert.Lenf(t, channels[i], 1, "session %d stopped being routable when a neighbour was removed", i)
	}
	// And the removed ones really are gone from the table.
	conn.mu.RLock()
	sessions := len(conn.sessions)
	conn.mu.RUnlock()
	assert.Equal(t, len(keys)/2, sessions)
}

// Admitting a session must cost one session's work, whatever is already
// registered. On a server that is the admission cost per connecting client,
// paid on the write lock every inbound packet needs, so the shape of the curve
// is the thing and not the constant.
//
// The assertion is a ratio between the first batch and the last rather than a
// budget, because a ratio does not care how fast the machine is. Rebuilding the
// whole table per admission makes the fourth batch cost about seven times the
// first; the incremental table measures 3.7 ms, 3.5, 3.8, 3.6 for batches of a
// thousand, and stays flat out to eight thousand sessions.
//
// The keys are derived outside the timed region, and each session gets its own,
// which is what a server sees: the tag comes from a per-connection exporter
// secret, so two sessions share a bucket only on a 2^-64 collision. Handing
// every session the same keys measures the collision instead, where the bucket
// itself grows and the copy that keeps it safe to read is O(bucket).
func TestDiscoAdmissionCostDoesNotGrowWithTheTable(t *testing.T) {
	if testing.Short() {
		t.Skip("times 8000 admissions")
	}
	_, conn := newDiscoConn(t)

	const batch = 2000
	const batches = 4
	var first, last time.Duration
	for b := range batches {
		keys := make([]*DiscoKeys, batch)
		for i := range keys {
			secret := append([]byte(nil), discoSecret...)
			secret[0], secret[1], secret[2] = byte(b), byte(i), byte(i>>8)
			var err error
			keys[i], err = NewDiscoKeys(secret, false)
			require.NoError(t, err)
		}
		start := time.Now()
		for i := range batch {
			_, err := conn.AddDiscoSession(discoSessionID(b*batch+i), keys[i], discoPeerN(b*batch+i))
			require.NoError(t, err)
		}
		elapsed := time.Since(start)
		t.Logf("sessions %d..%d admitted in %v", b*batch, (b+1)*batch, elapsed)
		if b == 0 {
			first = elapsed
		}
		last = elapsed
	}
	assert.Less(t, last, 5*first,
		"the cost of admitting a session grows with the number already registered: "+
			"the tag table is being rebuilt per admission")
}

func discoSessionID(i int) string {
	return "session-" + strconv.Itoa(i)
}

func BenchmarkDiscoSessionAdmission(b *testing.B) {
	keys, err := NewDiscoKeys(discoSecret, false)
	require.NoError(b, err)
	for _, n := range []int{500, 1000, 2000, 4000} {
		b.Run(strconv.Itoa(n)+"-sessions", func(b *testing.B) {
			for b.Loop() {
				b.StopTimer()
				conn, err := NewDiscoPacketConn(obfuscatedSocket{newDiscoSocket(), discoObfuscatorName}, 1)
				require.NoError(b, err)
				b.StartTimer()
				for i := range n {
					if _, err := conn.AddDiscoSession(discoSessionID(i), keys, discoPeerN(i)); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				_ = conn.Close()
				b.StartTimer()
			}
		})
	}
}

// The tag rotates every two minutes and a receiver holds three epochs at once,
// so the table has to be rebuilt as epochs pass and not only when sessions come
// and go. A receiver that noticed late would have dropped the sender's packets
// in between, and disco does not retransmit.
func TestDiscoTagTableFollowsTheEpoch(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, server := discoTestKeys(t)
	events, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)
	firstEpoch := conn.epoch

	// Two epochs on, the sender's tag is outside the table the conn built at
	// admission -- that is the window the rebuild exists to close.
	now = now.Add(2 * discoEpoch)
	wire, err := EncodeDisco(discoTestPackets()[0], server, 1, now, 900)
	require.NoError(t, err)

	read := readInBackground(conn)
	sock.deliver(append([]byte(nil), wire...))
	got := requireRead(t, read)
	require.NoError(t, got.err)
	assert.Len(t, got.data, 900, "a tag two epochs old still routed")
	assert.Empty(t, events)

	conn.refreshTags()
	assert.NotEqual(t, firstEpoch, conn.epoch, "the table did not move to the new epoch")

	read = readInBackground(conn)
	sock.deliver(append([]byte(nil), wire...))
	sock.deliver([]byte("data packet"))
	require.NoError(t, requireRead(t, read).err)
	requireEvent(t, events)
}

// Within an epoch the ticker must leave the table alone. Rebuilding it on every
// tick would put the whole table's worth of HKDF on the lock inbound packets
// need, four times a minute, for nothing.
//
// A sentinel entry is what makes that observable: a rebuild replaces the map and
// the sentinel goes with it.
// The rebuild has to publish a *fresh* map, not add to the one already there.
//
// A reviewer swapped the fresh map for the existing one and every test passed,
// which is what this closes. Adding to the old map never removes anything, so a
// session goes on answering to every tag it has ever held: the +-120s the
// three-epoch window is meant to tolerate widens without limit, and the table
// grows by three entries per session per epoch for as long as the socket lives.
// Both halves are asserted, because the size alone would be satisfied by a
// table that dropped the wrong entries.
func TestDiscoTagTableDropsTheEpochsItLeaves(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, server := discoTestKeys(t)
	events, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	// Sealed under the epoch the session was admitted in, and kept.
	stale, err := EncodeDisco(discoTestPackets()[0], server, 1, now, 900)
	require.NoError(t, err)

	for range 5 {
		now = now.Add(discoEpoch)
		conn.refreshTags()
	}

	conn.mu.RLock()
	tags := len(conn.byTag)
	conn.mu.RUnlock()
	assert.Equal(t, discoEpochsHeld, tags,
		"the table kept tags from epochs the session has left; it grows for the life of the socket")

	read := readInBackground(conn)
	sock.deliver(stale)
	sock.deliver([]byte("data packet"))
	got := requireRead(t, read)
	require.NoError(t, got.err)
	assert.Len(t, got.data, 900,
		"a tag five epochs old still routed; the previous epochs' tags outlived their window")
	assert.Empty(t, events)
}

// A bucket that is already in the tag table must never be written to.
//
// dispatch takes a bucket under the read lock and then walks it with the lock
// released, so every update has to publish a new slice instead of editing the
// one a reader may be holding. The test watches each bucket's whole backing
// array, slack capacity included, because that slack is exactly where an
// in-place append lands and it is invisible to anything that only compares the
// values a bucket currently holds.
//
// The sessions share one key schedule so that they share one tag: buckets hold
// a single session unless two collide, and a bucket of one has no room to be
// mutated wrongly. The rebuild before the snapshot is what gives the buckets
// their slack, since it grows them with plain append.
func TestDiscoTagBucketsAreNeverWrittenInPlace(t *testing.T) {
	_, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, _ := discoTestKeys(t)
	for i := range 3 {
		_, err := conn.AddDiscoSession(discoSessionID(i), client, discoPeerN(i))
		require.NoError(t, err)
	}
	now = now.Add(discoEpoch)
	conn.refreshTags()

	// An admission appends, so the slack is where a mistake would land and the
	// buckets must have some for the check to mean anything.
	watched := watchDiscoBuckets(t, conn, true)
	_, err := conn.AddDiscoSession(discoSessionID(3), client, discoPeerN(3))
	require.NoError(t, err)
	assertDiscoBucketsUntouched(t, watched, "admitting a session wrote into a bucket a reader may hold")

	// A removal compacts, which moves entries inside the length, so this half
	// needs no slack -- and has none, since appendDiscoBucket sizes exactly.
	watched = watchDiscoBuckets(t, conn, false)
	conn.RemoveDiscoSession(discoSessionID(1))
	assertDiscoBucketsUntouched(t, watched, "removing a session wrote into a bucket a reader may hold")
}

// discoBucketWatch remembers a bucket's slice header and a copy of its whole
// backing array, so a later comparison sees a write past the length as well as
// one inside it.
type discoBucketWatch struct {
	live []*discoSession
	was  []*discoSession
}

func watchDiscoBuckets(tb testing.TB, c *DiscoPacketConn, needSlack bool) []discoBucketWatch {
	tb.Helper()
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []discoBucketWatch
	for _, bucket := range c.byTag {
		full := bucket[:cap(bucket)]
		if needSlack {
			require.Greater(tb, cap(bucket), len(bucket),
				"the bucket has no slack capacity, so an in-place append would leave no trace to find")
		}
		out = append(out, discoBucketWatch{live: full, was: append([]*discoSession(nil), full...)})
	}
	require.NotEmpty(tb, out)
	return out
}

func assertDiscoBucketsUntouched(tb testing.TB, watched []discoBucketWatch, msg string) {
	tb.Helper()
	for _, w := range watched {
		assert.Truef(tb, slices.Equal(w.live, w.was), "%s: %v became %v", msg, w.was, w.live)
	}
}

func TestRefreshTagsDoesNothingWithinAnEpoch(t *testing.T) {
	_, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	client, _ := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)
	conn.mu.RLock()
	tags := len(conn.byTag)
	conn.mu.RUnlock()
	assert.Equal(t, discoEpochsHeld, tags, "a session should hold the previous, current and next epoch")

	var sentinel [discoTagLen]byte
	conn.mu.Lock()
	conn.byTag[sentinel] = nil
	conn.mu.Unlock()

	now = now.Add(10 * time.Second)
	conn.refreshTags()

	conn.mu.RLock()
	_, survived := conn.byTag[sentinel]
	conn.mu.RUnlock()
	assert.True(t, survived, "the tag table was rebuilt without the epoch having turned")
}

// A session admitted after the epoch has turned must land in the same table as
// the ones already there, or it would be routable and they would not.
func TestAddDiscoSessionAcrossAnEpochBoundary(t *testing.T) {
	sock, conn := newDiscoConn(t)
	now := time.Unix(1_700_000_000, 0)
	fixClock(conn, &now)

	first, firstPeer := discoTestKeys(t)
	firstEvents, err := conn.AddDiscoSession("first", first, discoServerAddr)
	require.NoError(t, err)

	otherSecret := append([]byte(nil), discoSecret...)
	otherSecret[0] ^= 0xff
	second, err := NewDiscoKeys(otherSecret, false)
	require.NoError(t, err)
	secondPeer, err := NewDiscoKeys(otherSecret, true)
	require.NoError(t, err)

	now = now.Add(2 * discoEpoch)
	secondEvents, err := conn.AddDiscoSession("second", second, discoServerAddr)
	require.NoError(t, err)

	read := readInBackground(conn)
	for _, peer := range []*DiscoKeys{firstPeer, secondPeer} {
		wire, err := EncodeDisco(discoTestPackets()[0], peer, 1, now, 900)
		require.NoError(t, err)
		sock.deliver(wire)
	}
	sock.deliver([]byte("data packet"))
	require.NoError(t, requireRead(t, read).err)

	assert.Len(t, firstEvents, 1, "the session admitted before the epoch turned stopped being routable")
	assert.Len(t, secondEvents, 1)
}

// The epoch ticker is a goroutine, so it has to start when there is something
// to rotate for and stop when there is not. Close stops it too, or a closed conn
// leaves one behind per connection the process ever made.
func TestDiscoEpochTickerStartsAndStops(t *testing.T) {
	_, conn := newDiscoConn(t)
	client, _ := discoTestKeys(t)

	conn.tickerMu.Lock()
	assert.Nil(t, conn.tickerStop, "a conn with no sessions is already running a ticker")
	conn.tickerMu.Unlock()

	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)
	conn.tickerMu.Lock()
	assert.NotNil(t, conn.tickerStop, "no ticker started; the tag table would never rotate")
	conn.tickerMu.Unlock()

	conn.RemoveDiscoSession("c")
	conn.tickerMu.Lock()
	assert.Nil(t, conn.tickerStop, "the ticker outlived the last session")
	conn.tickerMu.Unlock()
}

// Admissions and removals run concurrently on a server, and the two indexes
// they maintain -- the tag table and the peer index -- are both read with the
// lock released. This drives the two against each other so the race detector
// sees it, and asserts the invariant that ties the ticker to the table:
// a conn with a session registered is a conn whose tags still rotate.
//
// What it does NOT do is force the interleaving that made that invariant fail
// before syncEpochTicker existed. The old removal decided "the table is empty"
// under the session lock and acted on it after releasing it, so an admission
// landing in between lost its tag rotation -- but the admission has to finish
// its whole key derivation inside the two adjacent statements the removal has
// left, which needs the removing goroutine to be descheduled there. Staging it
// behind every lock the two share puts the removal first in every queue, and
// 3000 rounds of racing them under GOMAXPROCS=1 produced it zero times. The fix
// is that the decision and the act are now one step under tickerMu, and that is
// argued from the code rather than measured.
func TestDiscoSessionsAdmitAndRemoveConcurrently(t *testing.T) {
	client, _ := discoTestKeys(t)
	otherSecret := append([]byte(nil), discoSecret...)
	otherSecret[0] ^= 0xff
	other, err := NewDiscoKeys(otherSecret, false)
	require.NoError(t, err)

	for round := range 200 {
		_, conn := newDiscoConn(t)
		_, err := conn.AddDiscoSession("old", client, discoServerAddr)
		require.NoError(t, err)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			conn.RemoveDiscoSession("old")
		}()
		go func() {
			defer wg.Done()
			_, err := conn.AddDiscoSession("new", other, discoPeerN(round))
			assert.NoError(t, err)
		}()
		wg.Wait()

		conn.mu.RLock()
		live := len(conn.sessions)
		conn.mu.RUnlock()
		conn.tickerMu.Lock()
		running := conn.tickerStop != nil
		conn.tickerMu.Unlock()
		require.Equalf(t, live != 0, running,
			"round %d: %d sessions registered, ticker running = %v", round, live, running)
		require.NoError(t, conn.Close())
	}
}

func TestDiscoCloseStopsTheTicker(t *testing.T) {
	sock := newDiscoSocket()
	conn, err := NewDiscoPacketConn(obfuscatedSocket{sock, discoObfuscatorName}, 4)
	require.NoError(t, err)
	client, _ := discoTestKeys(t)
	_, err = conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)

	conn.tickerMu.Lock()
	done := conn.tickerDone
	conn.tickerMu.Unlock()
	require.NotNil(t, done)

	require.NoError(t, conn.Close())
	conn.tickerMu.Lock()
	assert.Nil(t, conn.tickerStop)
	conn.tickerMu.Unlock()
	assert.True(t, isClosed(done), "Close left the epoch ticker goroutine running")
}

// Stopping the ticker is only half of closing. The other half is that it stays
// stopped: the ticker's existence is decided by the session count, so a Close
// that left the table populated would hand the next add or remove a reason to
// start a fresh goroutine on a socket that can neither read nor write.
func TestDiscoCloseForgetsTheSessions(t *testing.T) {
	_, conn := newDiscoConn(t)
	client, _ := discoTestKeys(t)
	_, err := conn.AddDiscoSession("c", client, discoServerAddr)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	conn.mu.RLock()
	sessions, tags := len(conn.sessions), len(conn.byTag)
	conn.mu.RUnlock()
	assert.Zero(t, sessions, "Close left a session's key schedule on a dead conn")
	assert.Zero(t, tags, "Close left the tag table populated")
	conn.peerMu.RLock()
	peers := len(conn.byPeer)
	conn.peerMu.RUnlock()
	assert.Zero(t, peers, "Close left the peer index populated")

	conn.RemoveDiscoSession("c")
	conn.tickerMu.Lock()
	assert.Nil(t, conn.tickerStop, "a removal after Close started a ticker on a dead conn")
	conn.tickerMu.Unlock()

	// An admission is the one that reproduced it, and it now fails rather than
	// handing back a channel nothing will ever arrive on.
	_, err = conn.AddDiscoSession("later", client, discoServerAddr)
	assert.ErrorIs(t, err, net.ErrClosed)
	conn.tickerMu.Lock()
	assert.Nil(t, conn.tickerStop, "an admission after Close started a ticker on a dead conn")
	conn.tickerMu.Unlock()
}

// quic-go reaches through a PacketConn for the DF bit, path MTU detection and
// buffer sizing. The layers below already proxy them down to the socket; if this
// one did not proxy them on, wrapping the stack in a disco conn would silently
// turn them off.
func TestDiscoProxiesTheUDPFeatures(t *testing.T) {
	sock := &udpObfuscatedSocket{obfuscatedSocket: obfuscatedSocket{newDiscoSocket(), discoObfuscatorName}}
	conn, err := NewDiscoPacketConn(sock, 4)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.SyscallConn()
	assert.NoError(t, err)
	require.NoError(t, conn.SetReadBuffer(4096))
	require.NoError(t, conn.SetWriteBuffer(8192))
	assert.Equal(t, 4096, sock.readBuffer)
	assert.Equal(t, 8192, sock.writeBuffer)
}

// A conn whose socket does not carry them says so rather than pretending.
func TestDiscoReportsMissingUDPFeatures(t *testing.T) {
	_, conn := newDiscoConn(t)
	_, err := conn.SyscallConn()
	assert.ErrorIs(t, err, errors.ErrUnsupported)
	assert.ErrorIs(t, conn.SetReadBuffer(1), errors.ErrUnsupported)
	assert.ErrorIs(t, conn.SetWriteBuffer(1), errors.ErrUnsupported)
}

// The replay window is a window rather than "strictly greater than the last
// one" because disco sends a few packets a second and one reordering would
// otherwise be counted as a loss -- and the selector's decision to abandon a
// path is made out of exactly those counts.
func TestDiscoReplayWindow(t *testing.T) {
	var w discoReplayWindow
	assert.False(t, w.accept(0), "sequence zero is not a sequence number")

	assert.True(t, w.accept(1))
	assert.False(t, w.accept(1), "a duplicate was accepted")
	assert.True(t, w.accept(2))

	// Reordering inside the window is delivered, once.
	assert.True(t, w.accept(6))
	assert.True(t, w.accept(4))
	assert.True(t, w.accept(3))
	assert.False(t, w.accept(4))
	assert.True(t, w.accept(5))
	assert.True(t, w.accept(7))

	// Anything 64 or more behind the high-water mark is outside the window and
	// cannot be told from a replay.
	assert.True(t, w.accept(200))
	assert.True(t, w.accept(200-63))
	assert.False(t, w.accept(200-64))
	assert.False(t, w.accept(7))

	// A jump past the window clears it rather than shifting the old bits along.
	// Everything behind the new mark is unseen, so a packet that was merely late
	// is delivered -- once.
	assert.True(t, w.accept(1000))
	assert.True(t, w.accept(999), "a gap larger than the window left stale bits behind")
	assert.False(t, w.accept(999))
	assert.True(t, w.accept(1001))
}

// A conn with no sessions must not pay for the demux, because that is the state
// a server spends most of its life in and the state a packet flood arrives in.
// BenchmarkDiscoPacketConnWriteTo prices what the send path pays for routing a
// sample to the session that sent it, since a lock on the send path of every
// QUIC datagram is the thing this layer said it would not have. The socket
// underneath records into a slice, so the number is the conn's own overhead and
// not a syscall's; a real sendto is a microsecond or two on top of whichever
// figure this prints.
func BenchmarkDiscoPacketConnWriteTo(b *testing.B) {
	payload := make([]byte, 1439)
	for _, sessions := range []int{0, 1, 1000} {
		b.Run(strconv.Itoa(sessions)+"-sessions", func(b *testing.B) {
			sock, conn := newDiscoConn(b)
			sock.drop = true
			client, _ := discoTestKeys(b)
			for i := range sessions {
				if _, err := conn.AddDiscoSession(discoSessionID(i), client, discoPeerN(i)); err != nil {
					b.Fatal(err)
				}
			}
			// Addressed to the first session's path when there is one, and to
			// an address no session claims when there is not.
			addr := udpAddrFromAddrPort(discoPeerN(0))
			b.ResetTimer()
			for b.Loop() {
				if _, err := conn.WriteTo(payload, addr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDiscoPacketConnDispatch(b *testing.B) {
	packet := make([]byte, 1200)
	b.Run("no-sessions", func(b *testing.B) {
		_, conn := newDiscoConn(b)
		addr := udpAddrFromAddrPort(discoPeerAddr)
		b.ResetTimer()
		for b.Loop() {
			conn.dispatch(packet, addr)
		}
	})
	b.Run("one-session", func(b *testing.B) {
		_, conn := newDiscoConn(b)
		client, _ := discoTestKeys(b)
		if _, err := conn.AddDiscoSession("c", client, discoServerAddr); err != nil {
			b.Fatal(err)
		}
		addr := udpAddrFromAddrPort(discoPeerAddr)
		b.ResetTimer()
		for b.Loop() {
			conn.dispatch(packet, addr)
		}
	})
}

// TestDiscoSessionPeerInTheV4InV6FormIsStillCredited pins the normalisation the
// peer index needs.
//
// Datagrams reach WriteTo as a *net.UDPAddr and are keyed through
// addrToAddrPort, which unmaps. A caller building the address the ordinary way
// hands over the v4-in-v6 form. Storing one and looking up the other never
// matches, so the session is credited with nothing the connection sent and its
// probes are padded from an empty window.
func TestDiscoSessionPeerInTheV4InV6FormIsStillCredited(t *testing.T) {
	_, conn := newDiscoConn(t)
	client, _ := discoTestKeys(t)

	plain := netip.MustParseAddrPort("192.0.2.9:4433")
	mapped := netip.AddrPortFrom(netip.AddrFrom16(plain.Addr().As16()), plain.Port())
	require.True(t, mapped.Addr().Is4In6(), "the fixture must be in the form the bug needs")

	_, err := conn.AddDiscoSession("c", client, mapped)
	require.NoError(t, err)

	// 1439 rather than 1471: disco rides above the obfuscator, so what it sees
	// is the pre-obfuscation length, capped at quic-go's own maximum.
	for range 8 {
		_, err := conn.WriteTo(make([]byte, 1439), udpAddrFromAddrPort(plain))
		require.NoError(t, err)
	}
	assert.Equal(t, 1439, conn.PadToWireLen("c"),
		"the session was registered under a mapped address and credited with nothing sent to it")
}
