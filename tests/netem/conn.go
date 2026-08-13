package netem

import (
	"bytes"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// maxDatagramSize is the largest datagram the receive loop will accept. Bigger
// ones are truncated, exactly as a short recvfrom buffer would truncate them.
const maxDatagramSize = 65535

// defaultRecvQueue is how many delivered datagrams may wait for the application
// to read them. Past that the Conn drops, which is what a kernel socket does
// when its receive buffer overruns.
const defaultRecvQueue = 2048

type recvPacket struct {
	data []byte
	addr net.Addr
}

// Conn is a net.PacketConn whose datagrams cross an impaired link.
//
// It is deliberately not a *net.UDPConn, which means quic-go falls back to its
// portable path: no GSO, no ECN, no batched syscalls. Absolute numbers measured
// through a Conn are therefore not comparable to numbers measured on a bare
// socket. Take the baseline through a Conn with the Clean profile and compare
// against that.
type Conn struct {
	inner net.PacketConn
	ctrl  *Controller

	up, down *pipe
	recv     chan recvPacket
	overflow atomic.Uint64
	counters counters

	// seed1, seed2 seed the default pipes' draws; a per-candidate pipe derives
	// its own stream from them and the candidate's address (see peer.go).
	seed1, seed2 uint64

	// peers holds the candidates that have been given pipes of their own. It is
	// empty unless the Controller has per-candidate rules. nPeers mirrors its
	// size so the per-datagram fast path needs no lock.
	peersMu sync.RWMutex
	peers   map[netip.AddrPort]*peerLink
	nPeers  atomic.Int64

	rdDeadline *deadline

	closeOnce sync.Once
	closed    chan struct{}
	readDone  chan struct{}
}

// Wrap puts inner behind the link described by profile. The returned Conn owns
// inner and closes it on Close.
//
// The profile is fixed for the lifetime of the Conn; use a Controller when a
// test needs to change conditions while traffic is running.
func Wrap(inner net.PacketConn, profile Profile) *Conn {
	c := NewController(profile)
	return c.Wrap(inner)
}

func newConn(inner net.PacketConn, ctrl *Controller, seed1, seed2 uint64) *Conn {
	c := &Conn{
		inner:      inner,
		ctrl:       ctrl,
		recv:       make(chan recvPacket, defaultRecvQueue),
		seed1:      seed1,
		seed2:      seed2,
		rdDeadline: newDeadline(),
		closed:     make(chan struct{}),
		readDone:   make(chan struct{}),
	}
	// Separate streams per direction so that changing one direction's impairment
	// does not shift the other direction's draws.
	c.up = newPipe(func() Link { return ctrl.Profile().Up }, c.sendUp, &c.counters.up,
		true, rand.New(rand.NewPCG(seed1, seed2)))
	c.down = newPipe(func() Link { return ctrl.Profile().Down }, c.deliverDown, &c.counters.down,
		false, rand.New(rand.NewPCG(seed1, seed2+1)))
	go c.readLoop()
	return c
}

func (c *Conn) readLoop() {
	defer close(c.readDone)
	buf := make([]byte, maxDatagramSize)
	for {
		n, addr, err := c.inner.ReadFrom(buf)
		if n > 0 {
			// Downstream, the candidate is the source of the datagram.
			down := c.down
			if pl := c.peerFor(addr); pl != nil {
				down = pl.down
			}
			down.submit(bytes.Clone(buf[:n]), addr)
		}
		if err != nil {
			return
		}
	}
}

func (c *Conn) sendUp(data []byte, addr net.Addr) {
	_, _ = c.inner.WriteTo(data, addr)
}

func (c *Conn) deliverDown(data []byte, addr net.Addr) {
	select {
	case c.recv <- recvPacket{data: data, addr: addr}:
	default:
		c.overflow.Add(1)
	}
}

func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	// Prefer a datagram that is already here over a deadline that has just
	// expired, so a read cannot lose data it was about to return.
	select {
	case pkt := <-c.recv:
		return copy(p, pkt.data), pkt.addr, nil
	default:
	}
	select {
	case pkt := <-c.recv:
		return copy(p, pkt.data), pkt.addr, nil
	case <-c.rdDeadline.wait():
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo reports success even for datagrams the link drops. That is the whole
// point: a sender learns about loss from the peer, never from sendto.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	// Upstream, the candidate is the destination of the datagram.
	up := c.up
	if pl := c.peerFor(addr); pl != nil {
		up = pl.up
	}
	up.submit(p, addr)
	return len(p), nil
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		err = c.inner.Close()
		<-c.readDone
		c.up.stop()
		c.down.stop()
		c.stopPeers()
		if c.ctrl != nil {
			c.ctrl.retire(c)
		}
	})
	return err
}

func (c *Conn) LocalAddr() net.Addr { return c.inner.LocalAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	c.rdDeadline.set(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.rdDeadline.set(t)
	return nil
}

// SetWriteDeadline is a no-op: WriteTo never blocks, so there is nothing for a
// deadline to interrupt.
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// Stats returns the counters accumulated by this Conn so far, over every
// candidate together.
func (c *Conn) Stats() Stats {
	total := Stats{
		Up:       c.counters.up.snapshot(),
		Down:     c.counters.down.snapshot(),
		Overflow: c.overflow.Load(),
	}
	for _, s := range c.peerStats() {
		total = total.add(s)
	}
	return total
}

var _ net.PacketConn = (*Conn)(nil)
