package realm

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/stun/v3"
)

const (
	defaultPunchEventBuffer = 16

	// pumpQueueSize bounds how many data packets the pump holds for a reader
	// that has not arrived yet. The pump only runs before QUIC owns the socket,
	// so anything queued here is at most a handshake packet that QUIC would
	// retransmit anyway; a bounded queue matters more than a lossless one.
	pumpQueueSize = 32
	// pumpReadSlice bounds how long StopPump waits for the pump goroutine to
	// notice it should exit.
	pumpReadSlice = 100 * time.Millisecond
	// pumpBufferSize takes the largest datagram a UDP socket can deliver: a
	// short buffer would truncate a data packet, and handing the reader a
	// truncated packet is worse than never having queued it.
	pumpBufferSize = 65535
)

var ErrInvalidPunchAttempt = errors.New("invalid punch attempt")

type PunchPacketEvent struct {
	AttemptID string
	From      netip.AddrPort
	Packet    PunchPacket
}

type STUNPacketEvent struct {
	Message *stun.Message
	Addr    netip.AddrPort
}

type punchAttempt struct {
	id     string
	key    punchKey
	events chan PunchPacketEvent
}

type pumpState struct {
	stop chan struct{}
	done chan struct{}
}

type queuedPacket struct {
	data []byte
	addr net.Addr
}

// PunchPacketConn routes registered punch packets to per-attempt event channels
// while exposing all other packets through the wrapped PacketConn for QUIC.
//
// It is meant to stay in the stack for the lifetime of the socket: attempts can
// be registered and dropped at any time, including while QUIC is running on top
// of it, which is what makes re-punching and STUN refresh after a network change
// possible.
type PunchPacketConn struct {
	net.PacketConn

	// udp is non-nil when the wrapped PacketConn is a *net.UDPConn. It is used
	// to expose UDP-specific methods (SyscallConn, SetReadBuffer,
	// SetWriteBuffer) so quic-go and obfs wrappers can keep their UDP
	// optimizations even when sitting above us.
	udp *net.UDPConn

	eventBuffer int

	mu       sync.RWMutex
	attempts map[string]*punchAttempt
	// byTag indexes attempts by their clear-text tag so an inbound packet costs
	// one map lookup instead of a trial decryption per in-flight attempt.
	byTag map[uint32][]*punchAttempt
	stun  chan STUNPacketEvent

	pumpMu sync.Mutex
	pump   atomic.Pointer[pumpState]
	queue  chan queuedPacket
	queued atomic.Bool
}

func NewPunchPacketConn(conn net.PacketConn, eventBuffer int) (*PunchPacketConn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: conn is nil", ErrInvalidPunchAttempt)
	}
	if eventBuffer <= 0 {
		eventBuffer = defaultPunchEventBuffer
	}
	udp, _ := conn.(*net.UDPConn)
	return &PunchPacketConn{
		PacketConn:  conn,
		udp:         udp,
		eventBuffer: eventBuffer,
		attempts:    make(map[string]*punchAttempt),
		byTag:       make(map[uint32][]*punchAttempt),
		stun:        make(chan STUNPacketEvent, eventBuffer),
		queue:       make(chan queuedPacket, pumpQueueSize),
	}, nil
}

// SyscallConn returns the underlying *net.UDPConn's syscall.RawConn. Returns
// errors.ErrUnsupported when the wrapped PacketConn is not a *net.UDPConn.
func (c *PunchPacketConn) SyscallConn() (syscall.RawConn, error) {
	if c.udp == nil {
		return nil, errors.ErrUnsupported
	}
	return c.udp.SyscallConn()
}

// SetReadBuffer proxies to the underlying *net.UDPConn. Returns
// errors.ErrUnsupported when the wrapped PacketConn is not a *net.UDPConn.
func (c *PunchPacketConn) SetReadBuffer(bytes int) error {
	if c.udp == nil {
		return errors.ErrUnsupported
	}
	return c.udp.SetReadBuffer(bytes)
}

// SetWriteBuffer proxies to the underlying *net.UDPConn. Returns
// errors.ErrUnsupported when the wrapped PacketConn is not a *net.UDPConn.
func (c *PunchPacketConn) SetWriteBuffer(bytes int) error {
	if c.udp == nil {
		return errors.ErrUnsupported
	}
	return c.udp.SetWriteBuffer(bytes)
}

func (c *PunchPacketConn) STUNEvents() <-chan STUNPacketEvent {
	return c.stun
}

// AddPunchAttempt registers an attempt and returns the channel its packets are
// delivered on. Each attempt gets its own channel so a slow or abandoned
// attempt cannot swallow another one's packets.
//
// Attempts are told apart by their metadata, so two attempts sharing metadata
// are the same attempt on the wire: their packets all go to whichever
// registered first.
func (c *PunchPacketConn) AddPunchAttempt(id string, meta PunchMetadata) (<-chan PunchPacketEvent, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: id is required", ErrInvalidPunchAttempt)
	}
	key, err := newPunchKey(meta)
	if err != nil {
		return nil, err
	}
	attempt := &punchAttempt{
		id:     id,
		key:    key,
		events: make(chan PunchPacketEvent, c.eventBuffer),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.attempts[id]; exists {
		return nil, fmt.Errorf("%w: duplicate id", ErrInvalidPunchAttempt)
	}
	c.attempts[id] = attempt
	c.byTag[key.tag] = append(c.byTag[key.tag], attempt)
	return attempt.events, nil
}

func (c *PunchPacketConn) RemovePunchAttempt(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	attempt, ok := c.attempts[id]
	if !ok {
		return
	}
	delete(c.attempts, id)
	bucket := c.byTag[attempt.key.tag]
	for i, other := range bucket {
		if other == attempt {
			bucket = append(bucket[:i], bucket[i+1:]...)
			break
		}
	}
	if len(bucket) == 0 {
		delete(c.byTag, attempt.key.tag)
	} else {
		c.byTag[attempt.key.tag] = bucket
	}
}

// StartPump drains the socket in the background so the demux keeps working
// while nobody is reading from the top of the stack: STUN discovery and hole
// punching both need inbound packets before QUIC exists.
//
// Data packets seen while pumping are queued (bounded) and handed to the next
// ReadFrom, so handing the socket to QUIC after StopPump loses nothing that
// arrived in between. While the pump runs, ReadFrom serves from that queue
// instead of the socket, so the two never split the packet stream between them.
func (c *PunchPacketConn) StartPump() {
	c.pumpMu.Lock()
	defer c.pumpMu.Unlock()
	if c.pump.Load() != nil {
		return
	}
	state := &pumpState{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	c.pump.Store(state)
	go c.runPump(state)
}

// StopPump stops the background reader and waits for it to exit, so the caller
// owns the socket again once it returns. Safe to call when no pump is running.
func (c *PunchPacketConn) StopPump() {
	c.pumpMu.Lock()
	defer c.pumpMu.Unlock()
	state := c.pump.Load()
	if state == nil {
		return
	}
	close(state.stop)
	<-state.done
	c.pump.Store(nil)
	c.queued.Store(len(c.queue) > 0)
	// The pump read with deadlines; leave none behind for the next reader.
	_ = c.PacketConn.SetReadDeadline(time.Time{})
}

func (c *PunchPacketConn) runPump(state *pumpState) {
	defer close(state.done)
	buf := make([]byte, pumpBufferSize)
	for {
		select {
		case <-state.stop:
			return
		default:
		}
		_ = c.PacketConn.SetReadDeadline(time.Now().Add(pumpReadSlice))
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			// The socket is gone; the next ReadFrom will surface the same error.
			return
		}
		if c.dispatch(buf[:n], addr) {
			continue
		}
		c.enqueue(buf[:n], addr)
	}
}

func (c *PunchPacketConn) enqueue(packet []byte, addr net.Addr) {
	queued := queuedPacket{data: append([]byte(nil), packet...), addr: addr}
	select {
	case c.queue <- queued:
		c.queued.Store(true)
	default:
		// Full: drop. Nothing but QUIC handshake packets can be here, and QUIC
		// retransmits.
	}
}

func (c *PunchPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if c.queued.Load() {
			select {
			case queued := <-c.queue:
				return copy(p, queued.data), queued.addr, nil
			default:
				c.queued.Store(false)
			}
		}
		if state := c.pump.Load(); state != nil && !isClosed(state.done) {
			// The pump owns the socket; take what it hands us rather than
			// racing it for packets. A pump that exits on its own (socket
			// error) drops us back to reading the socket directly, where the
			// same error surfaces.
			select {
			case queued := <-c.queue:
				return copy(p, queued.data), queued.addr, nil
			case <-state.done:
			}
			continue
		}
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

// dispatch reports whether the packet was consumed by the punch or STUN demux.
func (c *PunchPacketConn) dispatch(packet []byte, addr net.Addr) bool {
	if ev, ok := c.decodeSTUNPacket(packet); ok {
		c.emitSTUN(ev)
		return true
	}
	if attempt, ev, ok := c.decodePunchPacket(packet, addr); ok {
		emitPunch(attempt, ev)
		return true
	}
	return false
}

func (c *PunchPacketConn) decodeSTUNPacket(packet []byte) (STUNPacketEvent, bool) {
	if !stun.IsMessage(packet) {
		return STUNPacketEvent{}, false
	}
	msg, addr, err := parseSTUNBindingResponse(packet)
	if err != nil {
		return STUNPacketEvent{}, false
	}
	return STUNPacketEvent{Message: msg, Addr: addr}, true
}

func (c *PunchPacketConn) decodePunchPacket(packet []byte, from net.Addr) (*punchAttempt, PunchPacketEvent, bool) {
	tag, ok := punchPacketTag(packet)
	if !ok {
		return nil, PunchPacketEvent{}, false
	}
	fromAddr, ok := addrToAddrPort(from)
	if !ok {
		return nil, PunchPacketEvent{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	// The tag is 32 bits of hash over the attempt metadata, so a bucket holds
	// more than one attempt only on a hash collision. Walking it keeps that
	// case correct without making the common case cost more than a lookup.
	for _, attempt := range c.byTag[tag] {
		punchPacket, err := decodePunchPacket(packet, attempt.key)
		if err != nil {
			continue
		}
		return attempt, PunchPacketEvent{
			AttemptID: attempt.id,
			From:      fromAddr,
			Packet:    punchPacket,
		}, true
	}
	return nil, PunchPacketEvent{}, false
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func emitPunch(attempt *punchAttempt, ev PunchPacketEvent) {
	select {
	case attempt.events <- ev:
	default:
	}
}

func (c *PunchPacketConn) emitSTUN(ev STUNPacketEvent) {
	select {
	case c.stun <- ev:
	default:
	}
}
