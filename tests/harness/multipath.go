package harness

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// MultiPath exposes one server socket at several addresses.
//
// Each address is a leg: its own UDP socket on 127.0.0.1, relaying between the
// client and the real server socket. The server therefore sees a distinct
// source address per leg -- which is the shape a candidate set has on the wire,
// and the shape the server's path handling has to cope with -- while there is
// still only one server, one certificate and one authenticator.
//
// It is a forwarder rather than several server sockets because core/server
// takes exactly one Conn (core/server/config.go); several listeners is a P2
// change. A forwarder needs no root, binds only 127.0.0.1 (the macOS
// 127.0.0.0/8 restriction is a known trap here) and, unlike a real multi-homed
// setup, can be told to lie about source addresses -- see RewriteSourceTo.
//
// Impairment is not MultiPath's job. A leg is named by its address, and
// netem.Controller.SetFor takes an address, so "candidate 1 is dead" is
// Ctrl.SetFor(mp.Legs[1].Key(), netem.Blocked()) and lives in one place with
// every other impairment in the bed.
//
// Do not build this on extras/transport/udphop. Its PacketConn lies to the
// layer above in both directions: ReadFrom reports a constant u.Addr instead of
// the real source, and WriteTo ignores its addr argument entirely ("Skip the
// check for now, always write to the server"). A test bed whose whole purpose
// is to tell candidates apart by address cannot stand on a conn that erases the
// address.
type MultiPath struct {
	origin   *net.UDPAddr
	originAP netip.AddrPort
	Legs     []*Leg

	// client is the address the legs relay back to. There is one client per
	// MultiPath by construction, and a leg that has only ever been used as a
	// forged source has never seen it, so it is held here rather than per leg.
	client atomic.Pointer[net.UDPAddr]
}

// NewMultiPath puts n forwarding legs in front of server and registers their
// teardown with t.
func NewMultiPath(t testing.TB, server net.Addr, n int) *MultiPath {
	t.Helper()
	if n < 1 {
		t.Fatalf("multipath needs at least one leg, got %d", n)
	}
	origin, ok := server.(*net.UDPAddr)
	if !ok {
		t.Fatalf("multipath needs a UDP server address, got %T", server)
	}
	mp := &MultiPath{origin: origin, originAP: mustKey(t, origin)}
	for i := 0; i < n; i++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen leg %d: %v", i, err)
		}
		leg := &Leg{mp: mp, index: i, conn: conn, addr: conn.LocalAddr().(*net.UDPAddr)}
		leg.ap = mustKey(t, leg.addr)
		mp.Legs = append(mp.Legs, leg)
	}
	for _, leg := range mp.Legs {
		go leg.relay()
	}
	t.Cleanup(func() {
		for _, leg := range mp.Legs {
			_ = leg.conn.Close()
		}
	})
	return mp
}

// Origin is the real server socket, behind every leg.
func (m *MultiPath) Origin() net.Addr { return m.origin }

// Candidates is every leg's address, in leg order.
func (m *MultiPath) Candidates() []netip.AddrPort {
	out := make([]netip.AddrPort, len(m.Legs))
	for i, leg := range m.Legs {
		out[i] = leg.ap
	}
	return out
}

// Leg is one of the addresses a MultiPath answers on.
type Leg struct {
	mp    *MultiPath
	index int
	conn  *net.UDPConn
	addr  *net.UDPAddr
	ap    netip.AddrPort

	fromClient, toServer, fromServer, toClient, rewritten atomic.Uint64

	mu sync.Mutex
	// spoof is the leg whose socket this leg's upstream datagrams leave from,
	// and spoofN how many are left to divert (-1 for all of them).
	spoof  *Leg
	spoofN int64
}

// Addr is the address a client dials to reach the server through this leg.
func (l *Leg) Addr() net.Addr { return l.addr }

// Key is Addr in the form netem.Controller.SetFor takes.
func (l *Leg) Key() netip.AddrPort { return l.ap }

// RewriteSourceTo makes every datagram this leg forwards leave from other's
// socket, so the server sees other's address as the source while the client goes
// on using this leg. Passing nil restores the leg's own address.
//
// This is an on-path attacker, modelled exactly: it does not decrypt, modify or
// replay anything, it changes the source address of a genuine packet in flight.
// The point of having it in the bed is that the server's reaction to that is a
// security property, and a security property that is only described in prose is
// not defended by anything.
func (l *Leg) RewriteSourceTo(other *Leg) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.spoof, l.spoofN = other, -1
	if other == nil {
		l.spoofN = 0
	}
}

// RewriteNextTo diverts exactly the next n datagrams, then restores the leg's
// own address. One is enough to move a server that follows source addresses
// unconditionally; the count exists so a test can say so precisely.
func (l *Leg) RewriteNextTo(other *Leg, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if other == nil || n <= 0 {
		l.spoof, l.spoofN = nil, 0
		return
	}
	l.spoof, l.spoofN = other, int64(n)
}

// LegStats is what one leg carried. The counts are datagrams.
type LegStats struct {
	// FromClient arrived at this leg's socket from the client.
	FromClient uint64
	// ToServer left this leg's socket towards the server. A datagram diverted by
	// RewriteSourceTo counts on the leg it left from, not the one it arrived on,
	// because that is the source address the server sees.
	ToServer uint64
	// FromServer arrived at this leg's socket from the server. This is the
	// number that says where the server's return path currently points.
	FromServer uint64
	// ToClient left this leg's socket towards the client.
	ToClient uint64
	// Rewritten arrived on this leg and was sent out of another leg's socket.
	Rewritten uint64
}

// Stats reports what this leg has carried so far.
func (l *Leg) Stats() LegStats {
	return LegStats{
		FromClient: l.fromClient.Load(),
		ToServer:   l.toServer.Load(),
		FromServer: l.fromServer.Load(),
		ToClient:   l.toClient.Load(),
		Rewritten:  l.rewritten.Load(),
	}
}

func (l *Leg) relay() {
	buf := make([]byte, 65535)
	for {
		n, src, err := l.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		key, ok := netem.PeerKey(src)
		if !ok {
			continue
		}
		if key == l.mp.originAP {
			l.fromServer.Add(1)
			client := l.mp.client.Load()
			if client == nil {
				// The server answered on a leg the client has never used. That
				// only happens after a source-address rewrite, and only before
				// the client has sent anything at all.
				continue
			}
			if _, err := l.conn.WriteTo(buf[:n], client); err == nil {
				l.toClient.Add(1)
			}
			continue
		}
		l.fromClient.Add(1)
		if client, ok := src.(*net.UDPAddr); ok {
			l.mp.client.Store(client)
		}
		out := l.sendLeg()
		if out != l {
			l.rewritten.Add(1)
		}
		if _, err := out.conn.WriteTo(buf[:n], l.mp.origin); err == nil {
			out.toServer.Add(1)
		}
	}
}

func (l *Leg) sendLeg() *Leg {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.spoof == nil {
		return l
	}
	out := l.spoof
	if l.spoofN > 0 {
		l.spoofN--
		if l.spoofN == 0 {
			l.spoof = nil
		}
	}
	return out
}

func mustKey(t testing.TB, a net.Addr) netip.AddrPort {
	t.Helper()
	k, ok := netem.PeerKey(a)
	if !ok {
		t.Fatalf("cannot use %v as a candidate address", a)
	}
	return k
}
