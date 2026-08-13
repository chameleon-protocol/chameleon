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
// for loss. A fix that trades that away for politeness has broken it. What the
// numbers here can be compared against afterwards is in docs/research/brutal.md.

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
	assert.GreaterOrEqual(t, on.Goodput, off.Goodput,
		"loss compensation must buy back at least what it costs")
}

// TestBrutalOverDeclarationCost measures what an over-declared rate does to a
// bottleneck it does not own. It asserts only the direction, because the
// magnitude is the number the repair is meant to move: see
// docs/research/brutal.md for the recorded baseline.
func TestBrutalOverDeclarationCost(t *testing.T) {
	if testing.Short() {
		t.Skip("two full transfers over a 1MB/s link")
	}
	const linkRate = 1 << 20
	profile := netem.RateLimited(linkRate).WithRTT(50 * time.Millisecond).Named("rate1MB/s+rtt50ms")

	var matched, over brutalResult
	t.Run("declared=link", func(t *testing.T) {
		matched = measureBrutal(t, profile, harness.Bandwidth{BytesPerSec: linkRate}, 2<<20)
	})
	t.Run("declared=2x-link", func(t *testing.T) {
		over = measureBrutal(t, profile, harness.Bandwidth{BytesPerSec: 2 * linkRate}, 2<<20)
	})

	// Declaring twice the link rate cannot conjure capacity, so the extra bytes
	// are pure waste -- and on a shared bottleneck they are waste paid for by
	// whoever else is in the queue.
	assert.Greater(t, over.DropRate, matched.DropRate+0.05,
		"over-declaring must show up as drops at the bottleneck")
	assert.LessOrEqual(t, over.Goodput, matched.Goodput*1.05,
		"over-declaring buys the sender nothing")
	t.Logf("over-declaring 2x: %.2fx the bytes on the wire for %.2fx the goodput, p99 %v -> %v",
		float64(over.WireIn)/float64(matched.WireIn),
		over.Goodput/matched.Goodput,
		matched.LatencyP9, over.LatencyP9)
}
