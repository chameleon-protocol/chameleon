package brutal

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// The acceptance criteria from docs/research/brutal.md that can only be checked
// here. Several of them cannot be checked end to end at all: the tests module
// cannot import this package, and the one about packet number length is about
// bytes that header protection hides from the impairment layer.

// newSender builds a sender with an RTT source already installed, which is the
// state quic-go hands the controller in.
func newSender(bps uint64, disableComp bool, rtt *fakeRTT) *BrutalSender {
	b := NewBrutalSender(bps, disableComp)
	b.SetRTTStatsProvider(rtt.provider())
	return b
}

// packets is the window expressed the way every consumer of it uses it.
func packets(b *BrutalSender) float64 {
	return float64(b.GetCongestionWindow()) / float64(b.maxDatagramSize)
}

// The thresholds quic-go's Chrome-imitating packet number rule uses, copied
// from internal/protocol/packet_number.go (PacketNumberLengthForHeaderChrome:
// delta < 1<<8/4 is one byte, delta < 1<<16/4 is two, otherwise four). They are
// written out rather than imported because they live in an internal package of
// the fork. If a fork upgrade moves them, this test is where that surfaces.
const (
	chromePNLen1Limit = 1 << 8 / 4  // 64
	chromePNLen2Limit = 1 << 16 / 4 // 16384
)

func chromePNLen(cwndPackets float64) int {
	n := int64(cwndPackets)
	switch {
	case n < chromePNLen1Limit:
		return 1
	case n < chromePNLen2Limit:
		return 2
	default:
		return 4
	}
}

// TestCwndFloor is E3 at unit level: the window must never fall to the one or
// two datagrams that stalled short paths outright.
func TestCwndFloor(t *testing.T) {
	// A loopback round trip. This is the cell that used to hang.
	rtt := newFakeRTT(300*time.Microsecond, 300*time.Microsecond)
	t.Logf("%-14s %-12s %-10s", "declared B/s", "cwnd", "packets")
	for _, bps := range []uint64{1 << 20, 2 << 20, 8 << 20, 64 << 20} {
		b := newSender(bps, false, rtt)
		got := packets(b)
		t.Logf("%-14d %-12d %-10.1f", bps, b.GetCongestionWindow(), got)
		if got < cwndFloorPackets {
			t.Errorf("declared %d B/s at a %v round trip: cwnd is %.1f packets, floor is %d",
				bps, rtt.smoothed, got, cwndFloorPackets)
		}
	}
	// The floor is a floor and not a replacement: a declaration whose own
	// product already exceeds it must be left alone.
	b := newSender(1<<30, false, rtt)
	if packets(b) <= cwndFloorPackets {
		t.Errorf("1 GB/s should exceed the floor on its own, got %.1f packets", packets(b))
	}
}

// TestCwndRTTFloor is the other half of the short-path problem, and the one
// that only showed up on the bed. A window sized from a measured 300us round
// trip is a window sized from the host's scheduler: quic-go hands the sender
// its turn on a one millisecond pacing clock, so however short the path is, a
// millisecond of bytes has to be allowed outstanding or the sender spends most
// of that millisecond blocked. Measured with the floor absent, a 64 MB/s
// declaration over loopback delivered between 52% and 92% of it, run to run.
func TestCwndRTTFloor(t *testing.T) {
	const declared = 64 << 20
	fast := newSender(declared, false, newFakeRTT(50*time.Microsecond, 50*time.Microsecond))
	slow := newSender(declared, false, newFakeRTT(congestion.MinPacingDelay, congestion.MinPacingDelay))
	if got, want := fast.GetCongestionWindow(), slow.GetCongestionWindow(); got != want {
		t.Errorf("cwnd %d at a 50us round trip, %d at the %v pacing clock: the floor is not holding",
			got, want, congestion.MinPacingDelay)
	}
	// A millisecond of the declared rate, which is what the sender has to be
	// able to put out between two pacing decisions.
	want := congestion.ByteCount(float64(declared) * congestion.MinPacingDelay.Seconds() * congestionWindowMultiplier)
	if got := fast.GetCongestionWindow(); got != want {
		t.Errorf("cwnd %d, want %d", got, want)
	}
	// And a path that really is longer than the clock still sets its own size.
	long := newSender(declared, false, newFakeRTT(20*time.Millisecond, 20*time.Millisecond))
	if long.GetCongestionWindow() <= want {
		t.Errorf("a 20ms path must size its own window, got %d", long.GetCongestionWindow())
	}
}

// TestCwndCeiling is the absolute cap quic-go applies to each of its own
// controllers and Brutal did not have.
func TestCwndCeiling(t *testing.T) {
	// A declaration and a path that between them ask for far more than the cap.
	rtt := newFakeRTT(2*time.Second, 2*time.Second)
	b := newSender(1<<30, false, rtt) // 1 GB/s
	if got := packets(b); got > congestion.MaxCongestionWindowPackets {
		t.Errorf("cwnd is %.0f packets, cap is %d", got, congestion.MaxCongestionWindowPackets)
	}
	t.Logf("1 GB/s at a 2s round trip: %d B, %.0f packets (cap %d)",
		b.GetCongestionWindow(), packets(b), congestion.MaxCongestionWindowPackets)
}

// TestCwndBoundsQueueing is the change the standing-queue defect turns on. The
// window may follow the queue -- it has to, because the controller cannot tell
// a queue of its own making from a path whose delay went up, and refusing to
// follow either cost 30% of the declared rate on a path that merely rerouted --
// but it must stop following at cwndRTTClampK times the path minimum. Past that
// point more queueing buys no more room to queue with, which is what breaks the
// feedback loop; the unclamped version reached 26214 packets in flight.
func TestCwndBoundsQueueing(t *testing.T) {
	const declared = 10 << 20
	const minRTT = 20 * time.Millisecond
	rtt := newFakeRTT(minRTT, minRTT)
	b := newSender(declared, false, rtt)

	base := b.GetCongestionWindow()
	want := congestion.ByteCount(cwndRTTClampK) * base // the ceiling the clamp sets
	t.Logf("declared %d B/s, minRTT %v: cwnd %d B (%.0f packets, %.1f x BDP), clamped ceiling %d B",
		declared, minRTT, base, packets(b),
		float64(base)/(float64(declared)*minRTT.Seconds()), want)
	for _, srtt := range []time.Duration{
		minRTT, 25 * time.Millisecond, 50 * time.Millisecond, 200 * time.Millisecond,
		800 * time.Millisecond, 1600 * time.Millisecond, 100 * minRTT,
	} {
		rtt.set(minRTT, srtt)
		got := b.GetCongestionWindow()
		if got > want {
			t.Errorf("SRTT %v: cwnd %d, ceiling %d -- the queue is still setting the window", srtt, got, want)
		}
		// Everything at or past the clamp has to sit exactly on the ceiling: a
		// window that kept creeping would be the same defect with a longer time
		// constant.
		if srtt >= cwndRTTClampK*minRTT && got != want {
			t.Errorf("SRTT %v is past the clamp: cwnd %d, want the ceiling %d", srtt, got, want)
		}
	}
	// Below the clamp it does track the smoothed round trip, which is what buys
	// back the throughput on a path whose own delay rose.
	rtt.set(minRTT, minRTT*3/2)
	if got := b.GetCongestionWindow(); got <= base || got >= want {
		t.Errorf("SRTT 1.5 x minRTT: cwnd %d, expected between %d and %d", got, base, want)
	}
	// And it tracks the path itself, which is the part that must survive.
	rtt.set(200*time.Millisecond, 200*time.Millisecond)
	if got := b.GetCongestionWindow(); got <= want {
		t.Errorf("a genuinely longer path must raise the window: %d vs %d", got, want)
	}
}

// TestCwndSurvivesAPathDelayRise is the unit statement of the regression that
// decided cwndRTTClampK, and the arithmetic behind the end-to-end cell in
// tests/e2e (TestBrutalSurvivesAPathDelayRise).
//
// A window of W bytes over a round trip of R caps the achievable rate at W/R
// whatever the pacer is asked for, so a window that does not follow the round
// trip is a rate that falls as the path lengthens. The path here is not
// queueing -- it is longer, which is a different thing and one the controller
// has no business punishing.
func TestCwndSurvivesAPathDelayRise(t *testing.T) {
	const declared = 1 << 20
	const minRTT = 20 * time.Millisecond
	// 2 x K: the window covers 2K x bps x minRTT, and delivering bps over R
	// needs bps x R, so the sender is rate-bound out to this multiple.
	const envelope = congestionWindowMultiplier * cwndRTTClampK
	rtt := newFakeRTT(minRTT, minRTT)
	b := newSender(declared, false, rtt)

	t.Logf("declared %d B/s, path minimum %v, envelope %d x minRTT", declared, minRTT, envelope)
	t.Logf("%-10s %-12s %-14s %-12s", "SRTT", "cwnd", "cwnd/SRTT", "vs declared")
	for mult := 1; mult <= envelope+2; mult++ {
		srtt := time.Duration(mult) * minRTT
		rtt.set(minRTT, srtt)
		cwnd := b.GetCongestionWindow()
		rate := float64(cwnd) / srtt.Seconds()
		t.Logf("%-10v %-12d %-14.0f %-12.3f", srtt, cwnd, rate, rate/declared)
		// The tolerance is one byte of integer truncation in the window, not
		// slack: at the envelope the two sides are the same number.
		if mult <= envelope && rate < declared*0.999 {
			t.Errorf("SRTT %v (%dx the path minimum, inside the %dx envelope): the window caps the sender at %.0f B/s, declared %d",
				srtt, mult, envelope, rate, declared)
		}
	}
}

// TestPacketNumberLengthIsBounded is E7, and it is the criterion the K = 2
// clamp deliberately gives ground on. On a client imitating Chrome the
// congestion window decides the packet number length, which is bytes on the
// wire that no amount of encryption hides. The unbounded window put an
// open-ended trajectory there: the length climbed with the queue and could jump
// the moment the path started losing. What is asserted now is what the clamp
// can actually deliver:
//
//   - past cwndRTTClampK x minRTT the length is a constant, because the window
//     is. That covers every standing queue a bottleneck can build, which is the
//     regime the original trajectory lived in;
//   - inside the clamp the window has a K-fold range, so the length may cross
//     at most one of Chrome's thresholds -- one band of movement, bounded, and
//     bounded by a constant that is in the source. At 1 MB/s over a 20ms path
//     it does exactly that (33 packets at rest, 66 clamped, across the 64
//     boundary), which is why this is asserted rather than claimed away;
//   - it does not move with loss. A length change triggered by a lossy path is
//     the worst shape this signal could take, and "compensation does not reach
//     the window" is what keeps it out.
//
// The alternative was pinning the window to the lifetime minimum, which does
// hold the length still and costs 30% of the declared rate on a path that
// merely rerouted. See docs/research/brutal.md section 3.7.
func TestPacketNumberLengthIsBounded(t *testing.T) {
	const minRTT = 20 * time.Millisecond
	rates := []uint64{
		100 << 10, 400 << 10, 1 << 20, 2 << 20, 10 << 20, 100 << 20, 1 << 30,
	}
	// The bands, in the order the length grows through them, so that "at most
	// one band of movement" is a subtraction rather than a case analysis.
	band := map[int]int{1: 0, 2: 1, 4: 2}

	t.Logf("%-16s %-12s %-12s %-10s %-10s", "declared B/s", "packets@min", "packets@clamp", "pn@min", "pn@clamp")
	for _, bps := range rates {
		rtt := newFakeRTT(minRTT, minRTT)
		b := newSender(bps, false, rtt)
		atRest := chromePNLen(packets(b))
		restPackets := packets(b)
		rtt.set(minRTT, cwndRTTClampK*minRTT)
		want := chromePNLen(packets(b))
		t.Logf("%-16d %-12.0f %-12.0f %-10d %-10d", bps, restPackets, packets(b), atRest, want)

		// One band at most between the two ends of the clamp's range.
		if d := band[want] - band[atRest]; d < 0 || d > 1 {
			t.Errorf("declared %d B/s: pn length %d at rest, %d at the clamp -- more than one band of movement",
				bps, atRest, want)
		}

		// Past the clamp, across every queue depth the path could develop, it
		// does not move at all.
		for mult := cwndRTTClampK; mult <= 100; mult++ {
			rtt.set(minRTT, time.Duration(mult)*minRTT)
			if got := chromePNLen(packets(b)); got != want {
				t.Errorf("declared %d B/s: pn length %d at SRTT %v x minRTT, %d at the clamp",
					bps, got, mult, want)
				break
			}
		}

		// And after enough loss to clamp the ack rate, which used to move the
		// window by 25% and could carry it across a threshold on its own.
		rtt.set(minRTT, minRTT)
		lossy := newSender(bps, false, rtt)
		feedLoss(lossy, 6, 500, 0.30)
		if lossy.ackRate == 1 {
			t.Fatalf("declared %d B/s: expected the ack rate to be clamped, got 1", bps)
		}
		if got := chromePNLen(packets(lossy)); got != atRest {
			t.Errorf("declared %d B/s: pn length %d under loss, %d without", bps, got, atRest)
		}
		off := newSender(bps, true, rtt)
		if got := chromePNLen(packets(off)); got != atRest {
			t.Errorf("declared %d B/s: pn length %d with compensation off, %d with it on", bps, got, atRest)
		}
	}
}

// TestNoCompensationWithoutAcks is E8 at unit level. A window in which nothing
// at all was acknowledged is a path that has gone away, and the one thing that
// must not happen when it comes back is a burst above the declared rate.
func TestNoCompensationWithoutAcks(t *testing.T) {
	rtt := newFakeRTT(20*time.Millisecond, 20*time.Millisecond)
	b := newSender(2<<20, false, rtt)

	// A blackhole: the loss detection timer fires with losses and no acks, which
	// is exactly how quic-go calls the controller on that path.
	for s := 1; s <= 6; s++ {
		b.OnCongestionEventEx(0, monotime.Time(time.Duration(s)*time.Second),
			nil, make([]congestion.LostPacketInfo, 100))
	}
	if b.ackRate != 1 {
		t.Errorf("ackRate = %.2f after a blackhole, want 1: the path came back and this is 1/%.2f = x%.2f the declared rate",
			b.ackRate, b.ackRate, 1/b.ackRate)
	}
	// The rate on the wire is the thing that actually matters.
	if got := pacedRate(b, time.Second, 100*time.Microsecond); got > 1.05*(2<<20) {
		t.Errorf("paced at %.0f B/s after a blackhole, declared %d B/s", got, 2<<20)
	}

	// Real loss with acks alongside it still compensates. The rule is about the
	// absence of evidence, not about the loss rate being high.
	c := newSender(2<<20, false, rtt)
	feedLoss(c, 6, 500, 0.50)
	if c.ackRate != minAckRate {
		t.Errorf("ackRate = %.2f under 50%% loss with acks arriving, want the %.2f floor", c.ackRate, minAckRate)
	}
}

// TestDelayGate is E4 at unit level: the same loss rate compensated on a path
// that is not queueing and not compensated on one that is.
func TestDelayGate(t *testing.T) {
	const minRTT = 20 * time.Millisecond
	const declared = 2 << 20

	// Random loss on an unqueued path: compensate.
	clean := newFakeRTT(minRTT, minRTT)
	a := newSender(declared, false, clean)
	feedLoss(a, 6, 500, 0.10)
	if a.ackRate >= 1 {
		t.Errorf("unqueued path with 10%% loss: ackRate = %.3f, want below 1", a.ackRate)
	}
	if wire := pacedRate(a, time.Second, 100*time.Microsecond); wire < 1.05*declared {
		t.Errorf("unqueued path: wire rate %.0f B/s, expected compensation above the declared %d", wire, declared)
	}

	// The same loss with the round trip inflated well past the path minimum:
	// the loss is the queue overflowing, and adding 25% more would only deepen
	// it. The rate must fall back to the declared rate and no further.
	queued := newFakeRTT(minRTT, 2*minRTT)
	c := newSender(declared, false, queued)
	feedLoss(c, 6, 500, 0.10)
	if c.ackRate != 1 {
		t.Errorf("queued path with 10%% loss: ackRate = %.3f, want exactly 1", c.ackRate)
	}
	wire := pacedRate(c, time.Second, 100*time.Microsecond)
	if math.Abs(wire-declared)/declared > 0.02 {
		t.Errorf("queued path: wire rate %.0f B/s, want the declared %d -- the gate must withdraw compensation, not back off",
			wire, declared)
	}

	// Hysteresis: shutting at 1.5x and reopening at 1.25x means a path sitting
	// between the two keeps whatever state it was in.
	h := newSender(declared, false, queued)
	feedLossFrom(h, 1, 6, 500, 0.10)
	if !h.congested {
		t.Fatalf("gate should be shut at SRTT = 2 x minRTT")
	}
	queued.set(minRTT, time.Duration(1.4*float64(minRTT))) // between the two ratios
	feedLossFrom(h, 7, 6, 500, 0.10)
	if !h.congested {
		t.Errorf("gate reopened at 1.4x minRTT; it should not until 1.25x")
	}
	queued.set(minRTT, time.Duration(1.1*float64(minRTT)))
	feedLossFrom(h, 13, 6, 500, 0.10)
	if h.congested {
		t.Errorf("gate still shut at 1.1x minRTT")
	}
}

// TestECNClosesTheGate covers the one explicit congestion signal that does not
// require a drop. It cannot be exercised end to end: the impairment layer is
// not a *net.UDPConn, so quic-go never sets a codepoint on the bed.
func TestECNClosesTheGate(t *testing.T) {
	rtt := newFakeRTT(20*time.Millisecond, 20*time.Millisecond) // no queueing to infer from
	b := newSender(2<<20, false, rtt)

	// ECN arrives through the non-extended callback with a zero lost byte count.
	b.OnCongestionEvent(1, 0, 0)
	if b.pendingECNCE != 1 {
		t.Fatalf("a CE report left %d marks pending, want 1", b.pendingECNCE)
	}
	feedLoss(b, 1, 500, 0.10)
	if !b.congested {
		t.Errorf("a CE mark should shut the delay gate on its own, with no queueing to infer from")
	}
	if b.ackRate != 1 {
		t.Errorf("a CE mark should withdraw compensation: ackRate = %.3f", b.ackRate)
	}

	// Ordinary loss reaches the same callback with a real length, and must not
	// be mistaken for a CE mark.
	//
	// The assertion is on the state, in the same event, and deliberately not on
	// the ack rate afterwards. congested is latched, and on a path whose
	// smoothed round trip equals its minimum the very next event unlatches it --
	// so a sender that counted every loss as a CE mark still ends a six second
	// feed with a compensating ack rate, and an assertion sited there sees
	// nothing wrong. Removing the lostBytes test from OnCongestionEvent has to
	// fail here.
	c := newSender(2<<20, false, rtt)
	c.OnCongestionEvent(1, 1200, 0)
	if c.pendingECNCE != 0 {
		t.Fatalf("an ordinary loss was recorded as %d pending CE marks", c.pendingECNCE)
	}
	feedLossFrom(c, 1, 1, 500, 0.10)
	if c.congested {
		t.Errorf("the delay gate shut on an unqueued path: a lost packet was read as a CE mark")
	}
	if c.ackRate >= 1 {
		t.Errorf("a lost packet is not an ECN mark: ackRate = %.3f", c.ackRate)
	}
}

// TestCompensationDoesNotReachCwnd: the divisor buys extra bytes on the wire
// because they are expected to be dropped. Those bytes do not need in-flight
// allowance of their own, and giving them some inflated the queue by a further
// 25% for nothing.
func TestCompensationDoesNotReachCwnd(t *testing.T) {
	rtt := newFakeRTT(20*time.Millisecond, 20*time.Millisecond)
	base := newSender(10<<20, false, rtt)
	lossy := newSender(10<<20, false, rtt)
	feedLoss(lossy, 6, 500, 0.30)

	if lossy.ackRate == 1 {
		t.Fatal("setup: expected the ack rate to be clamped")
	}
	if got, want := lossy.GetCongestionWindow(), base.GetCongestionWindow(); got != want {
		t.Errorf("cwnd under loss %d, without loss %d: compensation is still reaching the window", got, want)
	}
	// The wire rate is where it belongs, and is unchanged.
	on := pacedRate(lossy, time.Second, 100*time.Microsecond)
	if on < 1.2*(10<<20) {
		t.Errorf("compensation must still show up as rate: %.0f B/s for a declared %d", on, 10<<20)
	}
}

// TestSampleCountHysteresis: a flow hovering at the sample threshold used to
// swing its send rate by 25% with nothing else changing.
func TestSampleCountHysteresis(t *testing.T) {
	rtt := newFakeRTT(20*time.Millisecond, 20*time.Millisecond)
	b := newSender(2<<20, false, rtt)

	// Above the entry threshold: compensating.
	feedLossFrom(b, 1, 6, 12, 0.25) // 12 packets/s x 5s = 60 samples
	if !b.compensating {
		t.Fatalf("60 samples should clear the entry threshold of %d", minSampleCount)
	}
	// Dropping to 45, which is under the entry threshold but over the exit one.
	feedLossFrom(b, 7, 6, 9, 0.22) // 9 x 5 = 45
	if !b.compensating {
		t.Errorf("45 samples is between the %d entry and %d exit thresholds; state should be held",
			minSampleCount, minSampleCountExit)
	}
	// And below the exit threshold it really does stop.
	feedLossFrom(b, 13, 6, 6, 0.33) // 30
	if b.compensating {
		t.Errorf("30 samples is below the exit threshold of %d", minSampleCountExit)
	}
}

// TestSpuriousLossIsTakenBack: quic-go notices packets it declared lost and
// then received, but only tells the qlog. Left uncorrected, a reordering path
// reads as a lossy one forever and gets 25% more bytes it did not need.
func TestSpuriousLossIsTakenBack(t *testing.T) {
	rtt := newFakeRTT(20*time.Millisecond, 20*time.Millisecond)
	b := newSender(2<<20, false, rtt)

	lost := make([]congestion.LostPacketInfo, 100)
	for i := range lost {
		lost[i].PacketNumber = congestion.PacketNumber(i)
	}
	b.OnCongestionEventEx(0, monotime.Time(time.Second), make([]congestion.AckedPacketInfo, 300), lost)
	reordered := b.ackRate
	if reordered >= 1 {
		t.Fatalf("setup: 100 of 400 declared lost should have lowered the ack rate, got %.3f", reordered)
	}

	// All hundred turn up in the next acknowledgement.
	late := make([]congestion.AckedPacketInfo, 100)
	for i := range late {
		late[i].PacketNumber = congestion.PacketNumber(i)
	}
	b.OnCongestionEventEx(0, monotime.Time(time.Second), late, nil)
	if b.ackRate != 1 {
		t.Errorf("ackRate = %.3f after every declared loss was acknowledged, want 1", b.ackRate)
	}

	// Genuine loss, never acknowledged, still counts.
	c := newSender(2<<20, false, rtt)
	c.OnCongestionEventEx(0, monotime.Time(time.Second), make([]congestion.AckedPacketInfo, 300), lost)
	c.OnCongestionEventEx(0, monotime.Time(time.Second), make([]congestion.AckedPacketInfo, 10), nil)
	if c.ackRate >= 1 {
		t.Errorf("ackRate = %.3f with the losses unacknowledged, want below 1", c.ackRate)
	}

	// The bookkeeping must not grow without bound on a path that only loses.
	d := newSender(2<<20, false, rtt)
	for s := 1; s <= 30; s++ {
		batch := make([]congestion.LostPacketInfo, 1000)
		for i := range batch {
			batch[i].PacketNumber = congestion.PacketNumber(s*1000 + i)
		}
		d.OnCongestionEventEx(0, monotime.Time(time.Duration(s)*time.Second),
			make([]congestion.AckedPacketInfo, 1000), batch)
	}
	if len(d.lostPNs) > spuriousLossTrackLimit {
		t.Errorf("tracking %d packet numbers, limit is %d", len(d.lostPNs), spuriousLossTrackLimit)
	}
	t.Logf("after 30s of 1000 losses/s, tracking %d packet numbers", len(d.lostPNs))
}

// TestSetBPS covers the contract E6 asks for, starting with the value that used
// to crash: the pacer divides by the rate.
func TestSetBPS(t *testing.T) {
	rtt := newFakeRTT(20*time.Millisecond, 20*time.Millisecond)
	b := newSender(2<<20, false, rtt)

	// Zero is ignored, not applied. Anything else is a division by zero on the
	// next pacing decision.
	b.SetBPS(0)
	if got := b.bps.Load(); got != 2<<20 {
		t.Errorf("SetBPS(0) changed the rate to %d", got)
	}
	if got := b.TimeUntilSend(0); got < 0 { // the call that used to divide by zero
		t.Errorf("TimeUntilSend returned %v", got)
	}
	if got := pacedRate(b, time.Second, 100*time.Microsecond); math.Abs(got-(2<<20))/(2<<20) > 0.02 {
		t.Errorf("after SetBPS(0) the paced rate is %.0f B/s, want the original %d", got, 2<<20)
	}

	// A real change takes effect on the next pacing decision.
	c := newSender(2<<20, false, rtt)
	c.SetBPS(8 << 20)
	if got := pacedRate(c, time.Second, 100*time.Microsecond); math.Abs(got-(8<<20))/(8<<20) > 0.02 {
		t.Errorf("paced at %.0f B/s after SetBPS(8 MB/s)", got)
	}
	wantCwnd := congestion.ByteCount(float64(8<<20) * (20 * time.Millisecond).Seconds() * congestionWindowMultiplier)
	if got := c.GetCongestionWindow(); got != wantCwnd {
		t.Errorf("cwnd %d does not reflect the new rate", got)
	}

	// And the budget accumulated at the old rate does not survive it. Without
	// the reset, a drop from a high rate to a low one still releases a burst
	// paced by the rate that is gone.
	d := newSender(100<<20, false, rtt)
	d.OnPacketSent(simBase, 0, 0, d.maxDatagramSize, true)
	idle := simBase.Add(time.Second)
	before := d.pacer.Budget(idle)
	d.SetBPS(1 << 20)
	d.HasPacingBudget(idle) // a run loop entry point: this is where the reset lands
	after := d.pacer.Budget(idle)
	t.Logf("budget across a 100 MB/s -> 1 MB/s change: %d B -> %d B", before, after)
	if after >= before {
		t.Errorf("budget %d after the change, %d before: the old rate's budget survived", after, before)
	}
}

// TestSetBPSConcurrent is E6. The invariant being tested is the one written at
// the top of BrutalSender: everything except the two atomics belongs to a
// single goroutine, and whatever another goroutine wants changed is posted and
// picked up there. Run with -race.
func TestSetBPSConcurrent(t *testing.T) {
	rtt := newFakeRTT(20*time.Millisecond, 20*time.Millisecond)
	b := newSender(2<<20, false, rtt)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Exactly one run loop, because that is the invariant.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var now monotime.Time = simBase
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			now = now.Add(time.Millisecond)
			b.HasPacingBudget(now)
			b.TimeUntilSend(0)
			b.OnPacketSent(now, 0, congestion.PacketNumber(i), b.maxDatagramSize, true)
			b.GetCongestionWindow()
			b.CanSend(0)
			b.OnCongestionEventEx(0, now,
				make([]congestion.AckedPacketInfo, 10), make([]congestion.LostPacketInfo, 1))
			b.Stats()
		}
	}()

	// Two callers standing in for whatever is managing the path.
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			b.SetBPS(uint64(1<<20 + i))
			b.SetBPS(0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			b.OnPathChange()
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestOnPathChange: quic-go's minimum round trip is a lifetime minimum and
// never decays, so after a switch to a longer path a stale small one would hold
// the window below the new path's bandwidth-delay product and keep the delay
// gate permanently shut. The path layer says when that has happened.
func TestOnPathChange(t *testing.T) {
	// 8 MB/s rather than the 2 used elsewhere: at a 5ms round trip a smaller
	// declaration lands on the 32 packet floor, and a window held up by the
	// floor cannot show anything about the round trip it was sized from.
	rtt := newFakeRTT(5*time.Millisecond, 5*time.Millisecond)
	b := newSender(8<<20, false, rtt)
	short := b.GetCongestionWindow()

	// The path is replaced by a longer one. RTTStats keeps reporting the old
	// minimum, because that is what a lifetime minimum does, and the clamp is
	// relative to it -- so the window can open by cwndRTTClampK and no further,
	// which on a 16x longer path is nowhere near enough.
	rtt.set(5*time.Millisecond, 80*time.Millisecond)
	b.OnCongestionEventEx(0, monotime.Time(time.Second), make([]congestion.AckedPacketInfo, 100), nil)
	if got, ceiling := b.GetCongestionWindow(), congestion.ByteCount(cwndRTTClampK)*short; got != ceiling {
		t.Errorf("without being told, the window should sit on the stale minimum's clamp: %d, want %d",
			got, ceiling)
	}
	if !b.congested {
		t.Errorf("without being told, a 16x round trip reads as a queue")
	}

	b.OnPathChange()
	b.OnCongestionEventEx(0, monotime.Time(2*time.Second), make([]congestion.AckedPacketInfo, 100), nil)
	if got := b.GetCongestionWindow(); got <= short {
		t.Errorf("after a path change the window is %d, still at the old path's %d", got, short)
	}
	if b.congested {
		t.Errorf("after a path change the new path's own round trip is not a queue")
	}
	t.Logf("cwnd %d B on the old path, %d B after being told the path changed",
		short, b.GetCongestionWindow())
}

// TestTargetRegimeUnchanged is red line 5: on the path Brutal is for -- capacity
// to spare, no queue -- none of the new gates may fire, and the numbers must be
// what they were.
func TestTargetRegimeUnchanged(t *testing.T) {
	const declared = 2 << 20
	const rttVal = 50 * time.Millisecond
	rtt := newFakeRTT(rttVal, rttVal)
	b := newSender(declared, false, rtt)

	// The window is exactly what the shipped formula gave at SRTT = minRTT.
	want := congestion.ByteCount(float64(declared) * rttVal.Seconds() * congestionWindowMultiplier)
	if got := b.GetCongestionWindow(); got != want {
		t.Errorf("cwnd %d, the shipped formula gives %d", got, want)
	}
	// Random loss is still compensated for, exactly as before.
	feedLoss(b, 6, 500, 0.05)
	if b.ackRate != 0.95 {
		t.Errorf("ackRate %.3f under 5%% random loss, want 0.95", b.ackRate)
	}
	if wire := pacedRate(b, time.Second, 100*time.Microsecond); math.Abs(wire-declared/0.95)/(declared/0.95) > 0.02 {
		t.Errorf("wire rate %.0f B/s, want the compensated %.0f", wire, declared/0.95)
	}
	if b.congested {
		t.Error("the delay gate fired on a path with no queue")
	}
}
