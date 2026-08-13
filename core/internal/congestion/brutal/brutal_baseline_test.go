package brutal

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// Baseline measurements of the controller as shipped.
//
// The end-to-end bed in tests/ can see goodput and bytes on the wire, but it
// cannot see the two numbers that actually decide Brutal's behaviour: ackRate
// and the congestion window. Those are internal, and the tests module cannot
// even import this package. So the tables the repair will be judged against are
// produced here instead, by driving a real BrutalSender with synthetic ack and
// loss events and a fake RTT source.
//
// Nothing here asserts a threshold. These are `-v` tests whose output is the
// deliverable: run
//
//	go test ./internal/congestion/brutal/ -run Baseline -v
//
// and the tables come out. The assertions that do exist only check the
// measurement itself is sane, so that a silently broken harness cannot pass
// itself off as a result.

// fakeRTT is an RTTStatsProvider whose values the test sets directly, which is
// the only way to ask "what is cwnd at SRTT = 800ms" without waiting for a path
// that actually has one.
type fakeRTT struct {
	min      time.Duration
	smoothed time.Duration
}

func (f *fakeRTT) MinRTT() time.Duration                 { return f.min }
func (f *fakeRTT) LatestRTT() time.Duration              { return f.smoothed }
func (f *fakeRTT) SmoothedRTT() time.Duration            { return f.smoothed }
func (f *fakeRTT) MeanDeviation() time.Duration          { return 0 }
func (f *fakeRTT) MaxAckDelay() time.Duration            { return 0 }
func (f *fakeRTT) PTO(bool) time.Duration                { return f.smoothed * 2 }
func (f *fakeRTT) UpdateRTT(_, _ time.Duration)          {}
func (f *fakeRTT) SetMaxAckDelay(_ time.Duration)        {}
func (f *fakeRTT) SetInitialRTT(t time.Duration)         { f.smoothed = t }
func (f *fakeRTT) String() string                        { return f.smoothed.String() }
func (f *fakeRTT) set(min, smoothed time.Duration)       { f.min, f.smoothed = min, smoothed }
func newFakeRTT(min, smoothed time.Duration) *fakeRTT    { return &fakeRTT{min: min, smoothed: smoothed} }
func (f *fakeRTT) provider() congestion.RTTStatsProvider { return f }

// simBase is an arbitrary non-zero origin for the simulated clock. The pacer
// treats a zero lastSentTime as "never sent", so a simulation that starts at 0
// would measure the initial burst rather than the steady state.
const simBase = monotime.Time(time.Hour)

// feedLoss drives sec seconds of congestion events at the given packet rate and
// loss fraction, one event per second, and leaves the sender with the ackRate
// that window produced. It returns the loss fraction actually fed, which at low
// packet rates differs from the one asked for: a rate of 10 packets/s cannot
// carry 5% loss without rounding.
func feedLoss(b *BrutalSender, sec int, packetsPerSec int, loss float64) float64 {
	lost := int(math.Round(float64(packetsPerSec) * loss))
	acked := packetsPerSec - lost
	for s := 1; s <= sec; s++ {
		b.OnCongestionEventEx(0,
			monotime.Time(time.Duration(s)*time.Second),
			make([]congestion.AckedPacketInfo, acked),
			make([]congestion.LostPacketInfo, lost))
	}
	return float64(lost) / float64(packetsPerSec)
}

// pacedRate runs the pacer the way quic-go's send loop does -- ask for budget,
// send one datagram, repeat -- over dur of simulated time, and returns the
// bytes per second it let out. This is a measurement of the shipped Pacer, not
// a restatement of its formula: the burst cap and the budget arithmetic are
// both in the loop.
func pacedRate(b *BrutalSender, dur, step time.Duration) float64 {
	var sent congestion.ByteCount
	// One send to start the clock, so the first sample is not the idle burst.
	b.OnPacketSent(simBase, 0, 0, b.maxDatagramSize, true)
	for t := time.Duration(0); t < dur; t += step {
		now := simBase.Add(t)
		for b.HasPacingBudget(now) {
			b.OnPacketSent(now, 0, 0, b.maxDatagramSize, true)
			sent += b.maxDatagramSize
		}
	}
	return float64(sent) / dur.Seconds()
}

// TestBaselineLossCompensation is claim 1: what the ackRate divisor does to the
// rate on the wire, and to the rate that survives the link, as loss climbs.
func TestBaselineLossCompensation(t *testing.T) {
	const declared = 2 << 20 // 2 MB/s
	losses := []float64{0, 0.01, 0.05, 0.10, 0.20, 0.30, 0.50}

	t.Logf("declared = %d B/s, 500 packets/s of feedback, 5s window", declared)
	t.Logf("%-8s %-10s %-14s %-10s %-14s %-10s", "loss", "ackRate", "wire B/s", "wire x", "delivered B/s", "deliv x")
	for _, loss := range losses {
		on := NewBrutalSender(declared, false)
		on.SetRTTStatsProvider(newFakeRTT(20*time.Millisecond, 20*time.Millisecond).provider())
		feedLoss(on, 6, 500, loss)
		wire := pacedRate(on, 2*time.Second, 100*time.Microsecond)
		delivered := wire * (1 - loss)
		t.Logf("%-8s %-10.3f %-14.0f %-10.3f %-14.0f %-10.3f",
			fmt.Sprintf("%.0f%%", loss*100), on.ackRate, wire, wire/declared, delivered, delivered/declared)
	}

	t.Log("with disableLossCompensation = true:")
	for _, loss := range losses {
		off := NewBrutalSender(declared, true)
		off.SetRTTStatsProvider(newFakeRTT(20*time.Millisecond, 20*time.Millisecond).provider())
		feedLoss(off, 6, 500, loss)
		wire := pacedRate(off, 2*time.Second, 100*time.Microsecond)
		t.Logf("%-8s %-10.3f %-14.0f %-10.3f %-14.0f %-10.3f",
			fmt.Sprintf("%.0f%%", loss*100), off.ackRate, wire, wire/declared, wire*(1-loss), wire*(1-loss)/declared)
	}

	// The measurement is only worth reading if the pacer simulation tracks the
	// declared rate when nothing is impaired.
	clean := NewBrutalSender(declared, false)
	clean.SetRTTStatsProvider(newFakeRTT(20*time.Millisecond, 20*time.Millisecond).provider())
	if got := pacedRate(clean, 2*time.Second, 100*time.Microsecond); math.Abs(got-declared)/declared > 0.02 {
		t.Fatalf("pacer simulation is off: %.0f B/s for a declared %d B/s", got, declared)
	}
}

// TestBaselineCwndVsSRTT is claim 2: the congestion window is a linear function
// of the smoothed RTT and nothing else, so a queue that grows raises the ceiling
// on the bytes allowed to be in it.
func TestBaselineCwndVsSRTT(t *testing.T) {
	const declared = 10 << 20 // 10 MB/s
	const minRTT = 20 * time.Millisecond
	bdp := float64(declared) * minRTT.Seconds()

	rtt := newFakeRTT(minRTT, minRTT)
	b := NewBrutalSender(declared, false)
	b.SetRTTStatsProvider(rtt.provider())

	t.Logf("declared = %d B/s, minRTT = %v, BDP@minRTT = %.0f B", declared, minRTT, bdp)
	t.Logf("%-10s %-12s %-14s %-12s", "SRTT", "cwnd", "x BDP@minRTT", "in flight for")
	for _, srtt := range []time.Duration{
		1 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond,
		200 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond,
	} {
		rtt.set(minRTT, srtt)
		cwnd := b.GetCongestionWindow()
		t.Logf("%-10v %-12d %-14.1f %-12v", srtt, cwnd, float64(cwnd)/bdp,
			time.Duration(float64(cwnd)/float64(declared)*float64(time.Second)).Round(time.Millisecond))
	}

	// The mirror of the same formula: at a small SRTT the window collapses, and
	// its only floor is one datagram.
	t.Logf("cwnd floor, SRTT = 300us (loopback):")
	t.Logf("%-14s %-12s %-12s", "declared B/s", "cwnd", "packets")
	rtt.set(300*time.Microsecond, 300*time.Microsecond)
	for _, bps := range []uint64{1 << 20, 2 << 20, 8 << 20, 64 << 20} {
		s := NewBrutalSender(bps, false)
		s.SetRTTStatsProvider(rtt.provider())
		cwnd := s.GetCongestionWindow()
		t.Logf("%-14d %-12d %-12.1f", bps, cwnd, float64(cwnd)/float64(s.maxDatagramSize))
	}

	// CanSend is the only consumer of the window. If it never binds, the window
	// is not a control at all -- record where it starts to bind at a realistic
	// standing queue.
	rtt.set(minRTT, 200*time.Millisecond)
	cwnd := b.GetCongestionWindow()
	if !b.CanSend(cwnd - 1) {
		t.Fatalf("CanSend refused %d bytes below a %d byte window", cwnd-1, cwnd)
	}
	if b.CanSend(cwnd + 1) {
		t.Fatalf("CanSend allowed %d bytes above a %d byte window", cwnd+1, cwnd)
	}
}

// TestBaselineAckRateAmplifiesCwnd shows the two divisors are the same divisor:
// loss compensation raises the in-flight ceiling as well as the send rate.
func TestBaselineAckRateAmplifiesCwnd(t *testing.T) {
	const declared = 10 << 20
	rtt := newFakeRTT(20*time.Millisecond, 200*time.Millisecond)

	base := NewBrutalSender(declared, false)
	base.SetRTTStatsProvider(rtt.provider())
	clean := base.GetCongestionWindow()

	lossy := NewBrutalSender(declared, false)
	lossy.SetRTTStatsProvider(rtt.provider())
	feedLoss(lossy, 6, 500, 0.30) // past the clamp
	clamped := lossy.GetCongestionWindow()

	t.Logf("SRTT=200ms: cwnd at ackRate=1.00 is %d B, at ackRate=%.2f is %d B (x%.3f)",
		clean, lossy.ackRate, clamped, float64(clamped)/float64(clean))
}

// TestBaselineMinSampleCount answers whether a low-rate flow ever gets
// compensated at all: below the sample floor ackRate is pinned at 1 no matter
// how much of the flow is being lost.
func TestBaselineMinSampleCount(t *testing.T) {
	const loss = 0.05
	t.Logf("minSampleCount = %d over a %ds window; 5%% loss throughout", minSampleCount, pktInfoSlotCount)
	t.Logf("%-12s %-14s %-12s %-10s %-10s", "packets/s", "window total", "actual loss", "ackRate", "compensated")
	for _, pps := range []int{2, 5, 9, 10, 11, 20, 50, 200} {
		b := NewBrutalSender(2<<20, false)
		b.SetRTTStatsProvider(newFakeRTT(20*time.Millisecond, 20*time.Millisecond).provider())
		actual := feedLoss(b, 6, pps, loss)
		total := pps * pktInfoSlotCount
		t.Logf("%-12d %-14d %-12.3f %-10.3f %-10v", pps, total, actual, b.ackRate, b.ackRate != 1)
	}
	// An interactive flow at 100 bytes every 50ms is 20 packets/s, which is the
	// interesting cell: it is above the floor, so it does get compensated.
	b := NewBrutalSender(2<<20, false)
	b.SetRTTStatsProvider(newFakeRTT(20*time.Millisecond, 20*time.Millisecond).provider())
	feedLoss(b, 6, 20, loss)
	if b.ackRate == 1 {
		t.Errorf("20 packets/s was expected to clear minSampleCount, got ackRate=1")
	}
}

// TestBaselinePacerBurst records how big an idle pacer's first burst is, which
// is the shape a shared bottleneck sees rather than the average rate.
func TestBaselinePacerBurst(t *testing.T) {
	t.Logf("%-16s %-14s %-12s", "declared B/s", "burst bytes", "packets")
	for _, bps := range []uint64{1 << 20, 2 << 20, 10 << 20, 100 << 20} {
		b := NewBrutalSender(bps, false)
		b.SetRTTStatsProvider(newFakeRTT(20*time.Millisecond, 20*time.Millisecond).provider())
		// A pacer that has never sent reports its cap directly.
		budget := b.pacer.Budget(simBase)
		t.Logf("%-16d %-14d %-12.1f", bps, budget, float64(budget)/float64(b.maxDatagramSize))
	}
}

// TestBaselineRetransmissionTimeoutIsInert records claim 3 as a fact rather than
// a reading of the source: the empty OnRetransmissionTimeout cannot be a defect
// in the sender's own behaviour, because calling it changes nothing the sender
// exposes.
func TestBaselineRetransmissionTimeoutIsInert(t *testing.T) {
	b := NewBrutalSender(2<<20, false)
	b.SetRTTStatsProvider(newFakeRTT(20*time.Millisecond, 50*time.Millisecond).provider())
	feedLoss(b, 6, 500, 0.05)

	before := struct {
		cwnd    congestion.ByteCount
		ackRate float64
		budget  congestion.ByteCount
	}{b.GetCongestionWindow(), b.ackRate, b.pacer.Budget(simBase)}

	b.OnRetransmissionTimeout(true)
	b.OnRetransmissionTimeout(false)

	after := struct {
		cwnd    congestion.ByteCount
		ackRate float64
		budget  congestion.ByteCount
	}{b.GetCongestionWindow(), b.ackRate, b.pacer.Budget(simBase)}

	if before != after {
		t.Fatalf("OnRetransmissionTimeout is not inert: %+v -> %+v", before, after)
	}
	t.Logf("OnRetransmissionTimeout leaves cwnd=%d ackRate=%.2f budget=%d unchanged",
		after.cwnd, after.ackRate, after.budget)
}
