package obfs

import (
	"net"
	"sync"
	"syscall"
	"time"
)

const udpBufferSize = 2048 // QUIC packets are at most 1500 bytes long, so 2k should be more than enough

// obfuscator wraps a per-packet, length-preserving cipher.
// Obfuscate / Deobfuscate return the number of bytes written to out.
// If a packet is not valid, the methods should return 0.
type obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

var _ net.PacketConn = (*obfsPacketConn)(nil)

// bufPool hands out scratch buffers for obfuscation. A buffer per call rather
// than one shared buffer per connection is what lets ReadFrom and WriteTo run
// without holding a lock across the syscall: quic-go runs one sendQueue
// goroutine per connection, so a shared buffer serializes every client on a
// server behind a single mutex, and adding cores makes it worse rather than
// better. Obfuscators are responsible for their own internal synchronization.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpBufferSize)
		return &b
	},
}

type obfsPacketConn struct {
	Conn  net.PacketConn
	Obfs  obfuscator
	name  string
	stats *Stats
}

// ObfuscationName says which obfuscator this conn runs.
//
// It exists so a layer above can tell an obfuscated socket from a bare one
// without importing this package: realm's disco demux refuses to start on a
// socket whose packets go out in the clear, because measured against a real
// captured flow no disco envelope hides in bare QUIC -- the best candidate
// still showed 50% detection client-to-server and 24% server-to-client, caught
// within the first four packets. A deployment that believes it has multi-path
// failover and does not is worse off than one that knows it has none, so that
// has to be a startup error, and a startup error needs something to test.
func (c *obfsPacketConn) ObfuscationName() string { return c.name }

// obfuscationNamer is realm's obfuscatedPacketConn, restated here because that
// one is unexported in a package this one must not import. The assertions are
// what make the compiler notice if a wrapper stops carrying the method: without
// them the two halves of the contract are joined only by a runtime type
// assertion in realm, which fails by silently refusing to start.
//
// The wrapper each entry point returns is asserted, not the obfuscator inside
// it, because the wrapper is what realm is handed.
type obfuscationNamer interface{ ObfuscationName() string }

var (
	_ obfuscationNamer = (*obfsPacketConn)(nil)
	_ obfuscationNamer = (*obfsPacketConnUDP)(nil)
	_ obfuscationNamer = (*geckoPacketConn)(nil)
)

// udpLikePacketConn is the subset of *net.UDPConn methods that quic-go relies
// on for UDP-specific optimizations (DF/PMTU detection and recv/send buffer
// sizing). Anything that satisfies this interface — including a wrapper such
// as realm.PunchPacketConn that proxies these calls down to a *net.UDPConn —
// will keep those optimizations when wrapped in obfs.
type udpLikePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

// obfsPacketConnUDP is a special case of obfsPacketConn that wraps a
// UDP-flavored PacketConn. We pass additional methods through to quic-go to
// enable UDP-specific optimizations.
type obfsPacketConnUDP struct {
	*obfsPacketConn
	UDPConn udpLikePacketConn
}

// wrapPacketConn enables per-packet obfuscation on a net.PacketConn.
// The obfuscation is transparent to the caller - the n bytes returned by
// ReadFrom and WriteTo are the number of original bytes, not after
// obfuscation/deobfuscation.
func wrapPacketConn(conn net.PacketConn, ob obfuscator, name string) net.PacketConn {
	opc := &obfsPacketConn{
		Conn:  conn,
		Obfs:  ob,
		name:  name,
		stats: &Stats{},
	}
	if h, ok := ob.(statsHolder); ok {
		opc.stats = h.Stats()
	}
	if udpConn, ok := conn.(udpLikePacketConn); ok {
		return &obfsPacketConnUDP{
			obfsPacketConn: opc,
			UDPConn:        udpConn,
		}
	} else {
		return opc
	}
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buf := *bufp
	for {
		n, addr, err = c.Conn.ReadFrom(buf)
		if n <= 0 {
			return n, addr, err
		}
		n = c.Obfs.Deobfuscate(buf[:n], p)
		if n > 0 || err != nil {
			return n, addr, err
		}
		// Invalid packet, try again. Nothing above us will ever hear about it,
		// so count it - see Stats.
		c.stats.Dropped.Add(1)
	}
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buf := *bufp
	nn := c.Obfs.Obfuscate(p, buf)
	_, err = c.Conn.WriteTo(buf[:nn], addr)
	if err == nil {
		n = len(p)
	}
	return n, err
}

// Stats returns the counters for packets this connection refused. The returned
// pointer is live: read it whenever, the counters keep moving.
func (c *obfsPacketConn) Stats() *Stats {
	return c.stats
}

func (c *obfsPacketConn) Close() error {
	return c.Conn.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// UDP-specific methods below

func (c *obfsPacketConnUDP) SetReadBuffer(bytes int) error {
	return c.UDPConn.SetReadBuffer(bytes)
}

func (c *obfsPacketConnUDP) SetWriteBuffer(bytes int) error {
	return c.UDPConn.SetWriteBuffer(bytes)
}

func (c *obfsPacketConnUDP) SyscallConn() (syscall.RawConn, error) {
	return c.UDPConn.SyscallConn()
}
