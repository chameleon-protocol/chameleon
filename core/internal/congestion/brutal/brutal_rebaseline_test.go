package brutal

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// What the path minimum is rebaselined from after OnPathChange, and what it is
// deliberately not rebaselined from.
//
// Every expected value below is either a round trip this file feeds the sender
// itself or a figure that lives outside the controller -- quic-go's smoothed
// round trip filter length, quic-go's round trip for a path it has never
// measured, P1's post-switch acceptance window. None of them is read back out
// of rebaselineWindow or rebaselineMinSamples: an assertion whose expected
// value comes from the constant under test asserts nothing about it, which is
// the methodology docs/research/brutal.md section 5 E10 was written to stop
// this package repeating.

const (
	// oldPathMin is the previous path's lifetime minimum, which is what
	// RTTStats keeps reporting after the switch and what the estimate must fall
	// back to for as long as the new path's own minimum is not yet known.
	oldPathMin = 20 * time.Millisecond
	// queuedRTT is what the new path measures while something is queueing on
	// it, and newPathMin what the same path measures once that has drained.
	queuedRTT  = 260 * time.Millisecond
	newPathMin = 60 * time.Millisecond

	// unknownPathRTT is quic-go's DefaultInitialRTT (internal/utils/rtt_stats.go)
	// -- the round trip it assumes for a path it has never measured. It is the
	// only path-independent unit of "one round trip" available to a test that
	// is describing a path nobody has seen yet.
	unknownPathRTT = 100 * time.Millisecond

	// srttFilterLen is 1/rttAlpha (internal/utils/rtt_stats.go, rttAlpha =
	// 0.125): how many samples quic-go's own smoothed round trip needs before
	// the previous path has been filtered out of it.
	srttFilterLen = 8
)

// feedRebaseline drives n acknowledgement events, one every interval starting
// at from, each carrying a round trip of latest. Only the latest sample is
// moved: the smoothed round trip is left where the caller put it, so a floor
// built from the wrong one of the two is visible rather than coincidental.
//
// It returns the time the next event would fall on, so that consecutive calls
// describe one continuous timeline.
func feedRebaseline(b *BrutalSender, rtt *fakeRTT, from monotime.Time, n int, interval, latest time.Duration) monotime.Time {
	at := from
	for i := 0; i < n; i++ {
		rtt.setLatest(latest)
		b.OnCongestionEventEx(0, at,
			numbered(1, func(p *congestion.AckedPacketInfo, pn congestion.PacketNumber) { p.PacketNumber = pn }),
			nil)
		at = at.Add(interval)
	}
	return at
}

// TestRebaselineIgnoresTheQueueItSwitchedInto is the defect this rebaselining
// exists for. A candidate switch that happens to land while something is
// queueing on the new path measures the queue; a floor taken from those samples
// sizes a congestion window of 2K x bps x floor; a window that large keeps the
// queue full; and a queue that stays full never produces the smaller sample
// that would correct the floor. The error is self-sustaining, so it has to be
// prevented rather than recovered from.
func TestRebaselineIgnoresTheQueueItSwitchedInto(t *testing.T) {
	// 8 MB/s for the same reason TestOnPathChange uses it: a smaller
	// declaration lands on the packet floor, where the window says nothing
	// about the round trip it was sized from.
	rtt := newFakeRTT(oldPathMin, oldPathMin)
	b := newSender(8<<20, false, rtt)
	b.OnPathChange()

	// Three round trips' worth of a path nobody has measured, and twenty
	// samples -- well past the eight the sample count asks for. Every one of
	// them carries the queue. The sample count is satisfied here; elapsed time
	// is the only thing that is not, and it has to be enough on its own.
	const polluted = 20
	at := feedRebaseline(b, rtt, simBase, polluted, 3*unknownPathRTT/polluted, queuedRTT)
	if got := b.Stats().MinRTT; got != oldPathMin {
		t.Errorf("after %d queued samples over %v the estimate is %v; it must still be the previous path's %v, because a queue measured for a fraction of a second is not a path minimum",
			polluted, 3*unknownPathRTT, got, oldPathMin)
	}

	// The queue drains. Now the path is measurable, and what comes out has to
	// be the path rather than the queue that was in front of it.
	feedRebaseline(b, rtt, at, polluted, 3*unknownPathRTT/polluted, newPathMin)
	if got := b.Stats().MinRTT; got != newPathMin {
		t.Errorf("the estimate settled on %v; the path measures %v once its queue has gone, and %v was the queue",
			got, newPathMin, queuedRTT)
	}
}

// TestRebaselineCommitsInsideTheSwitchBudget is the other end of the same
// trade. While rebaselining is unfinished the sender is held to the previous
// path's minimum, which on a longer new path costs throughput -- so the window
// has to close, and close inside the budget P1 accepts a switch against.
func TestRebaselineCommitsInsideTheSwitchBudget(t *testing.T) {
	// The smoothed round trip is parked somewhere the sample values never go.
	// A floor rebaselined from SmoothedRTT rather than LatestRTT would show up
	// as this number.
	const parkedSRTT = 500 * time.Millisecond
	rtt := newFakeRTT(oldPathMin, parkedSRTT)
	b := newSender(8<<20, false, rtt)
	b.OnPathChange()

	// P1 accepts a switch on the throughput measured over the two seconds after
	// it (docs/design/p1-disco-selector.md, T6). Half of that window is the
	// most rebaselining may spend before it is the regression being measured.
	const budget = time.Second
	const samples = 40
	feedRebaseline(b, rtt, simBase, samples, budget/samples, newPathMin)
	if got := b.Stats().MinRTT; got != newPathMin {
		t.Errorf("after %v of clean samples the estimate is %v, want the measured %v: rebaselining has to be finished well inside P1's two second acceptance window, and it must come from the latest samples and not the smoothed round trip (%v)",
			budget, got, newPathMin, parkedSRTT)
	}
}

// TestRebaselineNeedsMoreThanOneFlight is why elapsed time alone is not the
// rule. Acknowledgement events are not independent observations of the path:
// a whole flight can be acknowledged in a handful of them, and a flight sees
// one queue state however long the sender waits before sending it.
func TestRebaselineNeedsMoreThanOneFlight(t *testing.T) {
	rtt := newFakeRTT(oldPathMin, oldPathMin)
	b := newSender(8<<20, false, rtt)
	b.OnPathChange()

	// Half of quic-go's own filter length, spread over a second and a half so
	// that elapsed time cannot be what is holding the commit back.
	const sparse = srttFilterLen / 2
	const interval = 500 * time.Millisecond
	at := feedRebaseline(b, rtt, simBase, sparse, interval, queuedRTT)
	if got := b.Stats().MinRTT; got != oldPathMin {
		t.Errorf("%d samples redefined the path minimum as %v; quic-go needs %d of them before its own smoothed round trip has forgotten the previous path, and a floor is worth less than a smoothed average, not more",
			sparse, got, srttFilterLen)
	}

	feedRebaseline(b, rtt, at, srttFilterLen-sparse, interval, queuedRTT)
	if got := b.Stats().MinRTT; got != queuedRTT {
		t.Errorf("after %d samples over %v the estimate is %v, want the only round trip the path ever showed, %v: waiting past the evidence is the failure the fallback costs throughput for",
			srttFilterLen, time.Duration(srttFilterLen)*interval, got, queuedRTT)
	}
}

// TestRebaselineRestartsOnASecondChange: P1 switches candidates more than once,
// and a rebaselining that carried the previous candidate's samples into the
// next one's window would commit a floor belonging to a path that is no longer
// underneath the connection.
func TestRebaselineRestartsOnASecondChange(t *testing.T) {
	rtt := newFakeRTT(oldPathMin, oldPathMin)
	b := newSender(8<<20, false, rtt)

	b.OnPathChange()
	at := feedRebaseline(b, rtt, simBase, 40, 25*time.Millisecond, newPathMin)
	if got := b.Stats().MinRTT; got != newPathMin {
		t.Fatalf("first path: estimate %v, want %v", got, newPathMin)
	}

	// A second switch, onto a path that is genuinely slower than the first. The
	// first path's 60ms must not survive as a floor here, and it must not
	// survive as a running minimum either -- the whole point of a rebaselined
	// floor is that it is allowed to go up when the path does.
	const slower = 180 * time.Millisecond
	b.OnPathChange()
	feedRebaseline(b, rtt, at, 40, 25*time.Millisecond, slower)
	if got := b.Stats().MinRTT; got != slower {
		t.Errorf("after a second switch the estimate is %v, want the new path's %v: samples from the path that was replaced are not evidence about the one that replaced it",
			got, slower)
	}
}
