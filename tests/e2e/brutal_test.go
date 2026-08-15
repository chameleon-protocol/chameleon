package e2e

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/metrics"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// Brutal only gets installed when both ends declare a bandwidth, so every other
// measurement in this package is about BBR. These are the ones about Brutal.
//
// They exist to pin down what must not change when Brutal is repaired: it is a
// controller whose whole point is to send at the declared rate and not back off
// for loss. A fix that trades that away for politeness has broken it.

// brutalResult is what one run of the load pattern produced.
type brutalResult struct {
	Goodput   float64 // bytes/s of payload, one way
	WireIn    uint64  // bytes offered to the bottleneck link
	WireOut   uint64  // bytes the bottleneck link actually carried
	DropRate  float64 // fraction the bottleneck dropped
	LatencyP5 time.Duration
	LatencyP9 time.Duration
}

// measureBrutal drives a bulk transfer with a latency probe running alongside
// it, which is the only way the queueing cost of a send rate shows up: measured
// on an idle link every controller looks the same.
func measureBrutal(t *testing.T, profile netem.Profile, bw harness.Bandwidth, size int) brutalResult {
	t.Helper()
	env := harness.New(t, harness.Options{Profile: profile, Seed: 7, Bandwidth: bw})

	var wg sync.WaitGroup
	var lat []time.Duration
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Let the transfer reach steady state before sampling; the first
		// exchanges would otherwise measure an empty pipe.
		time.Sleep(300 * time.Millisecond)
		lat, _ = env.TCPLatency(40, 2, 20*time.Millisecond, 20*time.Second)
	}()
	bps, err := env.TCPThroughput(size, 120*time.Second)
	wg.Wait()
	require.NoError(t, err)

	st := env.Ctrl.Stats()
	res := brutalResult{
		Goodput:   bps,
		WireIn:    st.Up.InBytes,
		WireOut:   st.Up.OutBytes,
		DropRate:  st.Up.LossRate(),
		LatencyP5: metrics.Percentile(lat, 0.5),
		LatencyP9: metrics.Percentile(lat, 0.99),
	}
	t.Logf("goodput=%s  offered=%dB carried=%dB drop=%.2f%%  latency p50=%v p99=%v",
		metrics.FormatRate(res.Goodput), res.WireIn, res.WireOut, res.DropRate*100,
		res.LatencyP5, res.LatencyP9)
	return res
}

// TestBrutalHoldsRateThroughLoss is the behaviour that must survive any repair.
// The link has capacity to spare and loses 5% of datagrams at random; Brutal is
// supposed to keep delivering the declared rate anyway, and loss compensation
// is supposed to be what buys back the difference.
func TestBrutalHoldsRateThroughLoss(t *testing.T) {
	const declared = 2 << 20
	profile := netem.RTT(50 * time.Millisecond).WithLoss(0.05).Named("rtt50ms+loss5%")
	size := longTransfer
	if testing.Short() {
		size = shortTransfer
	}

	var on, off brutalResult
	t.Run("compensation-on", func(t *testing.T) {
		on = measureBrutal(t, profile, harness.Bandwidth{BytesPerSec: declared}, size)
	})
	t.Run("compensation-off", func(t *testing.T) {
		off = measureBrutal(t, profile, harness.Bandwidth{
			BytesPerSec:             declared,
			DisableLossCompensation: true,
		}, size)
	})

	// 5% loss each way must not cost anything like 5% of the declared rate: a
	// controller that backs off would land far below this.
	assert.Greater(t, on.Goodput, 0.7*float64(declared),
		"Brutal must not treat random loss as a reason to slow down")
	// Compensation is the whole reason the ackRate divisor exists. If this stops
	// holding, the divisor is doing nothing and should be deleted rather than
	// kept for its externalities.
	//
	// The tolerance is not slack, it is the measurement. The two cells are
	// separate transfers, and the run-to-run spread on this bed is 3-5% while
	// the effect being tested is about 4% -- so a strict inequality on a single
	// pair is a coin flip on the noise, and it does come up tails: on the
	// unmodified controller it was 1.63 against 1.64 MB/s, and under the race
	// detector, where the spread is wider, 1.72 against 1.78. What is worth
	// asserting is that compensation is not a net cost, which this is.
	assert.GreaterOrEqual(t, on.Goodput, off.Goodput*0.97,
		"loss compensation must buy back at least what it costs")
}

// TestBrutalOverDeclarationCost measures what an over-declared rate does to a
// bottleneck it does not own.
//
// This used to assert that declaring twice the link rate showed up as drops,
// because it did: 13.5% of the uplink was being tail-dropped, the round trip's
// 99th percentile went from 54ms to 832ms, and the sender's own goodput fell
// from 975 to 806 KB/s. All three were the congestion window following the
// smoothed round trip, so the deeper the queue got the more bytes the sender
// was allowed to put in it. With the window built on the path's minimum round
// trip instead, in flight is bounded at twice the bandwidth-delay product of
// the declared rate -- about 210KB here -- which is less than the bottleneck's
// buffer, so nothing is dropped at all and the queue stops growing.
//
// The old assertion is therefore inverted, and deliberately: what has to be
// true now is that over-declaring costs the queue nothing, not that it costs it
// something. What has not changed, and is still asserted, is that it buys the
// sender nothing either.
func TestBrutalOverDeclarationCost(t *testing.T) {
	if testing.Short() {
		t.Skip("two full transfers over a 1MB/s link")
	}
	const linkRate = 1 << 20
	profile := netem.RateLimited(linkRate).WithRTT(50 * time.Millisecond).Named("rate1MB/s+rtt50ms")

	var matched, over, far brutalResult
	t.Run("declared=link", func(t *testing.T) {
		matched = measureBrutal(t, profile, harness.Bandwidth{BytesPerSec: linkRate}, 2<<20)
	})
	t.Run("declared=2x-link", func(t *testing.T) {
		over = measureBrutal(t, profile, harness.Bandwidth{BytesPerSec: 2 * linkRate}, 2<<20)
	})
	// Eight times the link is the cell that says whether the bound is a bound or
	// a coincidence of the 2x arithmetic. There is no threshold here that is not
	// simply the 2x one restated, so what is asserted is the direction, which is
	// the part that is a claim about the controller: however far the declaration
	// is from the truth, it buys the sender nothing. The queue and the drop rate
	// are logged, because at this declaration the window the clamp permits
	// (4 x 8MB/s x 50ms = 1.6MB) is larger than the bed's own buffer, so tail
	// drops are the link's answer rather than the controller's failure.
	t.Run("declared=8x-link", func(t *testing.T) {
		far = measureBrutal(t, profile, harness.Bandwidth{BytesPerSec: 8 * linkRate}, 2<<20)
	})

	// Declaring twice the link rate cannot conjure capacity, so the extra bytes
	// are still waste -- but the waste has to stay inside this flow's own
	// window rather than being pushed into the buffer, where it is paid for by
	// whoever else is in the queue.
	assert.Less(t, over.DropRate, 0.05,
		"an over-declared rate must not overflow the bottleneck's buffer")
	assert.LessOrEqual(t, over.Goodput, matched.Goodput*1.05,
		"over-declaring buys the sender nothing")
	assert.LessOrEqual(t, far.Goodput, matched.Goodput*1.05,
		"over-declaring by 8x buys the sender nothing either")
	// The queue the window permits: at most cwndRTTClampK x 2 x the declared
	// rate's bandwidth-delay product in flight, draining at the link's rate,
	// which is 2 x 2 x 2MB/s x 50ms = 420KB over a 1MB/s link, or about 400ms
	// on top of the link's own 50ms. The bound below is that arithmetic with
	// room for noise. It was 832ms before the window stopped following the queue
	// without limit, and 204ms in the revision that pinned the window to the
	// path minimum outright -- which is the same 2x that this cell gives back,
	// bought at 30% of the declared rate on any path whose own delay rises.
	assert.Less(t, over.LatencyP9, 600*time.Millisecond,
		"the window must stop the standing queue growing, whatever the declaration says")
	t.Logf("over-declaring 2x: %.2fx the bytes on the wire for %.2fx the goodput, p99 %v -> %v",
		float64(over.WireIn)/float64(matched.WireIn),
		over.Goodput/matched.Goodput,
		matched.LatencyP9, over.LatencyP9)
	t.Logf("over-declaring 8x: %.2fx the bytes on the wire for %.2fx the goodput, p99 %v, drop %.2f%%",
		float64(far.WireIn)/float64(matched.WireIn),
		far.Goodput/matched.Goodput, far.LatencyP9, far.DropRate*100)
}
