package netem

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Bottleneck is a shaper that several Conns contend for.
//
// Link.Rate gives every Conn its own token bucket and its own queue, which is
// perfect per-flow fairness by construction: one flow cannot take capacity from
// another, and cannot fill a buffer another flow has to queue behind. That is
// the wrong model for the question "what does an aggressive sender cost its
// neighbours", because the answer is fixed at "nothing" before the experiment
// starts.
//
// A Bottleneck is one bucket and one buffer for every Link that points at it.
// Reservations are served in call order under a single lock, so the flows share
// the capacity in proportion to how hard each one pushes, and a flow that keeps
// the buffer full makes its neighbour's datagrams tail-drop. That is the
// externality a rate-declaring controller has, and it cannot be seen any other
// way.
//
// The buffer is measured in bytes of outstanding debt rather than in queued
// datagrams, because the debt is what the bucket actually tracks: a datagram
// admitted when the bucket is 100ms behind will not leave for 100ms, which is
// the same thing as sitting in a 100ms buffer.
type Bottleneck struct {
	rate  float64 // bytes per second
	burst float64 // bucket depth in bytes
	limit float64 // maximum outstanding debt in bytes; beyond it the link tail-drops

	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time

	admitted atomic.Uint64
	dropped  atomic.Uint64
}

// NewBottleneck returns a shaper of bytesPerSec with a buffer of bufferDelay
// worth of traffic. A bufferDelay of zero picks 100ms, which is the order of a
// consumer access link's buffer and deep enough that a standing queue is
// visible as latency before it is visible as loss.
func NewBottleneck(bytesPerSec int64, bufferDelay time.Duration) *Bottleneck {
	if bufferDelay <= 0 {
		bufferDelay = 100 * time.Millisecond
	}
	rate := float64(bytesPerSec)
	burst := rate * burstWindow.Seconds()
	if burst < defaultBurstFloor {
		burst = defaultBurstFloor
	}
	return &Bottleneck{
		rate:  rate,
		burst: burst,
		limit: rate * bufferDelay.Seconds(),
	}
}

// reserve charges n bytes and returns when the datagram may leave. It reports
// false if the buffer was already full, which is a tail drop.
func (b *Bottleneck) reserve(now time.Time, n int) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lastRefill.IsZero() {
		b.tokens = b.burst
	} else {
		b.tokens = min(b.burst, b.tokens+now.Sub(b.lastRefill).Seconds()*b.rate)
	}
	b.lastRefill = now

	// Negative tokens are the backlog: bytes admitted but not yet due to leave.
	debt := -b.tokens
	if debt < 0 {
		debt = 0
	}
	if debt+float64(n) > b.limit {
		b.dropped.Add(1)
		return time.Time{}, false
	}
	release := now
	if b.tokens < float64(n) {
		release = now.Add(time.Duration((float64(n) - b.tokens) / b.rate * float64(time.Second)))
	}
	b.tokens -= float64(n)
	b.admitted.Add(1)
	return release, true
}

// BottleneckStats is what the shared shaper did, summed over every flow that
// crossed it. Per-flow numbers come from each Conn's own counters.
type BottleneckStats struct {
	Admitted uint64
	Dropped  uint64
}

func (s BottleneckStats) String() string {
	total := s.Admitted + s.Dropped
	var rate float64
	if total > 0 {
		rate = float64(s.Dropped) / float64(total)
	}
	return fmt.Sprintf("admitted=%d dropped=%d (%.2f%%)", s.Admitted, s.Dropped, rate*100)
}

// Stats returns what the shaper has seen.
func (b *Bottleneck) Stats() BottleneckStats {
	return BottleneckStats{Admitted: b.admitted.Load(), Dropped: b.dropped.Load()}
}

// WithSharedBottleneck returns a copy of p whose two directions are shaped by
// up and down. Either may be nil to leave that direction unshaped.
//
// Pass a different Bottleneck for each direction unless the point is to model a
// half-duplex medium: a real access link's uplink and downlink do not take
// capacity from each other.
//
// A shared Bottleneck overrides Rate, Burst and Queue on that direction: they
// describe a per-Conn shaper, and having both would mean two shapers in series.
func (p Profile) WithSharedBottleneck(up, down *Bottleneck) Profile {
	p.Up.Shared, p.Down.Shared = up, down
	return p
}
