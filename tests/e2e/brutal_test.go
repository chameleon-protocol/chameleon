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
	// This second assertion is narrower than it looks, and the narrowness is
	// deliberate rather than an oversight: what it says is that switching
	// compensation on is not a net cost at 5% loss, and that is all it says. It
	// cannot detect a divisor that does nothing, because a divisor that does
	// nothing makes the two cells identical and satisfies it.
	//
	// The tolerance is not slack, it is the measurement. The two cells are
	// separate transfers, and the run-to-run spread on this bed is 3-5% while
	// the effect at 5% loss is about 4% -- so a strict inequality on a single
	// pair is a coin flip on the noise, and it does come up tails: on the
	// unmodified controller it was 1.63 against 1.64 MB/s, and under the race
	// detector, where the spread is wider, 1.72 against 1.78.
	//
	// "The divisor is doing something" is therefore asserted where the effect is
	// bigger than the noise instead of here, in
	// TestBrutalCompensationOutsendsItsAbsence.
	assert.GreaterOrEqual(t, on.Goodput, off.Goodput*0.97,
		"loss compensation must not be a net cost")
}

// TestBrutalCompensationOutsendsItsAbsence is the assertion that the ackRate
// divisor does anything at all. If it fails, the divisor can be deleted; the
// case for keeping it rests on this and nothing else.
//
// It is measured at 20% loss and not at the 5% the test above uses, because
// only at 20% does the effect clear this bed's noise. ackRate is
// ackCount/(ackCount+lossCount) with a floor of minAckRate = 0.8, so the send
// rate compensation asks for is declared/ackRate: 1.05x at 5% loss, which is
// inside a 3-5% run-to-run spread, and the full 1.25x at 20%, which is not.
//
// What is compared is the rate bytes were offered to the link at, not goodput.
// Goodput is what the extra bytes buy, and at 20% loss that is a second-order
// question tangled up with retransmission timing; the rate is what the divisor
// directly decides, and the pacer is the only thing between the two. Measured
// with the two cells as fixed-size transfers first, the ratio came out at 1.147
// and 1.089 on consecutive runs -- because a fixed-size transfer's duration is
// decided by when its last retransmission landed, which at this loss rate is
// worth more than the effect. Backlogged for a fixed ten seconds instead, the
// same comparison gave 1.244, 1.227, 1.246, 1.258 and 1.238 over five runs,
// with the absolute figures landing on the arithmetic: 2.44-2.47 MB/s against a
// declared 2.00, and 1.96-1.99 MB/s with the divisor switched off.
//
// The bound is therefore 1.12: two thirds of the way from the inert value to
// the observed minimum, which is far enough below the measurement to survive a
// slower host and far enough above 1.00 to fail on a divisor that has quietly
// stopped dividing. It was not exercised under the race detector -- the test
// image has no cgo -- so the margin is sized for a spread wider than the one
// measured.
func TestBrutalCompensationOutsendsItsAbsence(t *testing.T) {
	if testing.Short() {
		t.Skip("two backlogged flows over a 20% lossy link, several seconds each")
	}
	const declared = 2 << 20
	const runFor = 10 * time.Second
	profile := netem.RTT(50 * time.Millisecond).WithLoss(0.20).Named("rtt50ms+loss20%")

	on := offeredRate(t, profile, harness.Bandwidth{BytesPerSec: declared}, runFor)
	off := offeredRate(t, profile, harness.Bandwidth{
		BytesPerSec:             declared,
		DisableLossCompensation: true,
	}, runFor)

	ratio := on / off
	t.Logf("at 20%% loss over %v, compensation offered %s against %s, x%.3f",
		runFor, metrics.FormatRate(on), metrics.FormatRate(off), ratio)
	assert.Greater(t, ratio, 1.12,
		"loss compensation is not raising the send rate: the ackRate divisor is inert")
}

// offeredRate runs a backlogged flow for d and reports how fast its uplink
// offered bytes to the link, from the link's own counters.
//
// A fixed duration rather than a fixed size, and a rate rather than a total,
// because the send rate is what the divisor decides and both other framings
// hide it. A fixed-size transfer at this loss rate ends on whenever its last
// retransmission happened to land, which is worth several percent of the
// elapsed time on its own; a total over a fixed duration is the same figure as
// the rate but harder to compare against the declaration.
func offeredRate(t *testing.T, profile netem.Profile, bw harness.Bandwidth, d time.Duration) float64 {
	t.Helper()
	env := harness.New(t, harness.Options{Profile: profile, Seed: 7, Bandwidth: bw})
	base := env.Ctrl.Stats()
	start := time.Now()
	_, err := env.TCPLoadFor(env.Client, d)
	elapsed := time.Since(start)
	require.NoError(t, err)
	st := env.Ctrl.Stats()
	offered := st.Up.InBytes - base.Up.InBytes
	rate := float64(offered) / elapsed.Seconds()
	t.Logf("declared %s, compensation=%v: offered %dB in %v = %s, drop %.2f%%",
		metrics.FormatRate(float64(bw.BytesPerSec)), !bw.DisableLossCompensation,
		offered, elapsed.Round(10*time.Millisecond), metrics.FormatRate(rate),
		st.Up.LossRate()*100)
	return rate
}

// TestBrutalDeliversItsRateOnALongPath is the case the deployment actually
// looks like: a client in a censored network and a server outside it, so the
// path is long from the first packet rather than having grown that way.
//
// It is the gap between the two path tests that already exist.
// TestBrutalRunsOnShortPaths covers a round trip near zero, which is where the
// window collapsed; TestBrutalSurvivesAPathDelayRise covers a round trip that
// went up under the sender, which is where the clamp binds. Neither says
// anything about a path that was always 200ms, and that one is decided by
// different arithmetic: the window is 2 x bps x minRTT with minRTT the real
// path, so it exceeds what the rate needs by construction, and the only other
// thing that could bind is flow control -- the BDP here is 20 Mbps x 200ms =
// 500KB against the core's 8MB stream and 20MB connection windows.
//
// The bound is 0.7 of the declaration, which is the same figure the two tests
// above use and is not a fresh invention. It has a great deal of room: measured
// over four runs the 200ms case came in at 0.870, 0.863, 0.860 and 0.840 of the
// declaration, against 0.958-0.974 at a zero round trip, and the whole of that
// gap is the transfer's first round trip, which a 4MB transfer at this rate
// spends about 12% of its life in. A tighter bound would be asserting the
// startup transient rather than the steady state.
func TestBrutalDeliversItsRateOnALongPath(t *testing.T) {
	if testing.Short() {
		t.Skip("a full transfer over a 200ms path")
	}
	const declared = 20e6 / 8 // 20 Mbps expressed the way the config wants it
	r := measureBrutal(t, netem.RTT(200*time.Millisecond),
		harness.Bandwidth{BytesPerSec: declared}, longTransfer)
	t.Logf("declared %s over a 200ms path: %s, %.1f%% of the declaration",
		metrics.FormatRate(declared), metrics.FormatRate(r.Goodput), r.Goodput/declared*100)

	assert.Greater(t, r.Goodput, 0.7*float64(declared),
		"a long path is not a reason to deliver less than the declared rate")
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
