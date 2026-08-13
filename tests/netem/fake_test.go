package netem

import (
	"bytes"
	"net"
	"sync"
	"time"
)

// fakeConn is an in-memory net.PacketConn standing in for the socket a Conn
// wraps. Tests use it instead of a loopback socket so that a measured drop is
// always the link's doing and never the kernel's.
type fakeConn struct {
	addr net.Addr
	in   chan []byte

	mu      sync.Mutex
	written []sent

	closeOnce sync.Once
	closed    chan struct{}
}

type sent struct {
	at   time.Time
	data []byte
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		addr:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		in:     make(chan []byte, 8192),
		closed: make(chan struct{}),
	}
}

func (f *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case data := <-f.in:
		return copy(p, data), f.addr, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakeConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-f.closed:
		return 0, net.ErrClosed
	default:
	}
	f.mu.Lock()
	f.written = append(f.written, sent{at: time.Now(), data: bytes.Clone(p)})
	f.mu.Unlock()
	return len(p), nil
}

func (f *fakeConn) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeConn) LocalAddr() net.Addr              { return f.addr }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// deliver feeds a datagram to the Conn's receive direction.
func (f *fakeConn) deliver(data []byte) { f.in <- data }

func (f *fakeConn) sent() []sent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sent(nil), f.written...)
}

func (f *fakeConn) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.written)
}

var _ net.PacketConn = (*fakeConn)(nil)
