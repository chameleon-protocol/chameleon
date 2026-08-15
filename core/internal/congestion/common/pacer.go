package common

import (
	"time"

	"github.com/chameleon-protocol/quic-go/congestion"
	"github.com/chameleon-protocol/quic-go/monotime"
)

const (
	// maxBurstPackets is quic-go's own figure (internal/congestion/pacer.go).
	// Keeping it is a fingerprint decision, not a performance one: the shape of
	// the first burst after an idle period is visible, and matching upstream is
	// the point.
	maxBurstPackets = 10

	// maxBurstPacingDelayMultiplier sizes the other half of the burst cap, the
	// one that binds at any rate above a few MB/s. Upstream quic-go accumulates
	// MinPacingDelay + TimerGranularity of bandwidth, which is 1ms + 1ms; this
	// tree had four, which doubled the burst against upstream for no stated
	// reason. Two restores it. TimerGranularity is not exported through the
	// congestion package, but is the same one millisecond
	// (quic-go internal/protocol/params.go: MinPacingDelay, TimerGranularity).
	//
	// Steady-state throughput does not depend on this -- budget only
	// accumulates while idle -- so what it changes is how blocky the injection
	// is after a pause, which is what a shared bottleneck's buffer sees.
	maxBurstPacingDelayMultiplier = 2
)

// Pacer implements a token bucket pacing algorithm.
type Pacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     monotime.Time
	getBandwidth     func() congestion.ByteCount // in bytes/s
}

func NewPacer(getBandwidth func() congestion.ByteCount) *Pacer {
	p := &Pacer{
		budgetAtLastSent: maxBurstPackets * congestion.InitialPacketSize,
		maxDatagramSize:  congestion.InitialPacketSize,
		getBandwidth:     getBandwidth,
	}
	return p
}

func (p *Pacer) SentPacket(sendTime monotime.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *Pacer) Budget(now monotime.Time) congestion.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	budget := p.budgetAtLastSent + (p.getBandwidth()*congestion.ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9
	if budget < 0 { // protect against overflows
		budget = congestion.ByteCount(1<<62 - 1)
	}
	return min(p.maxBurstSize(), budget)
}

func (p *Pacer) maxBurstSize() congestion.ByteCount {
	return max(
		congestion.ByteCount((maxBurstPacingDelayMultiplier*congestion.MinPacingDelay).Nanoseconds())*p.getBandwidth()/1e9,
		maxBurstPackets*p.maxDatagramSize,
	)
}

// TimeUntilSend returns when the next packet should be sent.
// It returns the zero value if a packet can be sent immediately.
func (p *Pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	bw := uint64(p.getBandwidth())
	// We might need to round up this value.
	// Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
	d := diff / bw
	// this is effectively a math.Ceil, but using only integer math
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(max(congestion.MinPacingDelay, time.Duration(d)*time.Nanosecond))
}

func (p *Pacer) SetMaxDatagramSize(s congestion.ByteCount) {
	p.maxDatagramSize = s
}

// Reset drops the budget accumulated so far, so that the next send is paced at
// the current bandwidth rather than partly funded by the previous one. A
// controller whose rate can be changed mid-connection needs this: without it,
// dropping from 100 MB/s to 1 MB/s still releases several hundred kilobytes at
// the old pace.
//
// Like every other method here it must be called from the connection's run
// loop, and only from there. None of this struct's state is synchronised, on
// purpose -- it is touched once per packet sent. A caller on some other
// goroutine that wants a reset has to post the request and let the run loop
// pick it up; see BrutalSender.SetBPS.
//
// lastSentTime is deliberately left alone. Zeroing it would read as "has never
// sent" and hand out a full idle burst, which is the opposite of draining.
func (p *Pacer) Reset() {
	p.budgetAtLastSent = 0
}
