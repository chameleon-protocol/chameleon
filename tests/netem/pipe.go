package netem

import (
	"bytes"
	"container/heap"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// packet is a datagram waiting for its release time inside a pipe.
type packet struct {
	data []byte
	addr net.Addr
	due  time.Time
	seq  uint64
}

// packetQueue orders packets by release time. seq breaks ties so that a link
// without jitter never reorders.
type packetQueue []*packet

func (q packetQueue) Len() int { return len(q) }

func (q packetQueue) Less(i, j int) bool {
	if q[i].due.Equal(q[j].due) {
		return q[i].seq < q[j].seq
	}
	return q[i].due.Before(q[j].due)
}

func (q packetQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

func (q *packetQueue) Push(x any) { *q = append(*q, x.(*packet)) }

func (q *packetQueue) Pop() any {
	old := *q
	n := len(old)
	p := old[n-1]
	old[n-1] = nil
	*q = old[:n-1]
	return p
}

// pipe applies one direction of a Profile to the datagrams handed to it.
//
// A datagram that survives the loss draw is passed to out, either inline on the
// caller's goroutine when the link adds neither delay nor rate limit, or from
// the pipe's own goroutine once its release time arrives.
type pipe struct {
	link func() Link // read per datagram, so a profile change lands immediately
	out  func(data []byte, addr net.Addr)
	ctr  *dirCounters

	// borrowed says that submit's caller owns the slice it passes, so queueing a
	// datagram has to copy it. The receive direction hands over freshly
	// allocated slices and leaves this false.
	borrowed bool

	mu         sync.Mutex
	rng        *rand.Rand
	q          packetQueue
	seq        uint64
	tokens     float64
	lastRefill time.Time

	wake    chan struct{}
	done    chan struct{}
	stopped chan struct{}
}

func newPipe(link func() Link, out func([]byte, net.Addr), ctr *dirCounters, borrowed bool, rng *rand.Rand) *pipe {
	p := &pipe{
		link:     link,
		out:      out,
		ctr:      ctr,
		borrowed: borrowed,
		rng:      rng,
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	go p.run()
	return p
}

// submit applies the link's impairment to one datagram. It reports whether the
// datagram survived; false means the link dropped it.
func (p *pipe) submit(data []byte, addr net.Addr) bool {
	link := p.link()
	n := len(data)
	p.ctr.in.Add(1)
	p.ctr.inBytes.Add(uint64(n))

	p.mu.Lock()
	if link.Blackhole || (link.Loss > 0 && p.rng.Float64() < link.Loss) {
		p.mu.Unlock()
		p.drop(n)
		return false
	}
	now := time.Now()
	if limit := link.queueLimit(); limit > 0 && len(p.q) >= limit {
		p.mu.Unlock()
		p.drop(n)
		return false
	}
	release := now
	if link.Rate > 0 {
		release = p.reserve(now, n, link)
	}
	due := release.Add(p.draw(link))
	if !due.After(now) {
		// Nothing to wait for. Staying on the caller's goroutine keeps an
		// unimpaired link a thin pass-through rather than a channel hop.
		p.mu.Unlock()
		p.deliver(data, addr, n)
		return true
	}
	if p.borrowed {
		data = bytes.Clone(data)
	}
	pkt := &packet{data: data, addr: addr, due: due, seq: p.seq}
	p.seq++
	heap.Push(&p.q, pkt)
	first := p.q[0] == pkt
	p.mu.Unlock()

	if first {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
	return true
}

// draw returns the delay for one datagram. Must hold p.mu.
func (p *pipe) draw(link Link) time.Duration {
	d := link.Delay
	if link.Jitter > 0 {
		d += time.Duration(p.rng.Int64N(2*int64(link.Jitter)+1)) - link.Jitter
	}
	if d < 0 {
		return 0
	}
	return d
}

// reserve charges n bytes to the token bucket and returns the time at which the
// datagram may leave. Tokens are allowed to go negative: the debt is what makes
// a backlog build up and drain in order. Must hold p.mu.
func (p *pipe) reserve(now time.Time, n int, link Link) time.Time {
	rate := float64(link.Rate)
	burst := float64(link.burst())
	if p.lastRefill.IsZero() {
		p.tokens = burst
	} else {
		p.tokens = math.Min(burst, p.tokens+now.Sub(p.lastRefill).Seconds()*rate)
	}
	p.lastRefill = now
	release := now
	if p.tokens < float64(n) {
		release = now.Add(time.Duration((float64(n) - p.tokens) / rate * float64(time.Second)))
	}
	p.tokens -= float64(n)
	return release
}

func (p *pipe) drop(n int) {
	p.ctr.dropped.Add(1)
	p.ctr.droppedBytes.Add(uint64(n))
}

func (p *pipe) deliver(data []byte, addr net.Addr, n int) {
	p.ctr.out.Add(1)
	p.ctr.outBytes.Add(uint64(n))
	p.out(data, addr)
}

func (p *pipe) run() {
	defer close(p.stopped)
	timer := time.NewTimer(math.MaxInt64)
	defer timer.Stop()
	for {
		var due []*packet
		p.mu.Lock()
		now := time.Now()
		for len(p.q) > 0 && !p.q[0].due.After(now) {
			due = append(due, heap.Pop(&p.q).(*packet))
		}
		wait := time.Duration(-1)
		if len(p.q) > 0 {
			wait = p.q[0].due.Sub(now)
		}
		p.mu.Unlock()

		for _, pkt := range due {
			p.deliver(pkt.data, pkt.addr, len(pkt.data))
		}
		if len(due) > 0 {
			// Delivery took time; recompute before sleeping on a stale deadline.
			continue
		}
		if wait < 0 {
			select {
			case <-p.wake:
			case <-p.done:
				return
			}
			continue
		}
		timer.Stop()
		timer.Reset(wait)
		select {
		case <-p.wake:
		case <-timer.C:
		case <-p.done:
			return
		}
	}
}

// stop shuts the pipe down and discards whatever is still in flight, which is
// what a closed socket does to the packets the network had not delivered yet.
func (p *pipe) stop() {
	close(p.done)
	<-p.stopped
	p.mu.Lock()
	p.q = nil
	p.mu.Unlock()
}
