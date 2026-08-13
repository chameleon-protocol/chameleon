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

// The end-to-end half of the acceptance criteria in docs/research/brutal.md.
// The rest are in the brutal package itself, because the two things that decide
// this controller's behaviour -- the ack rate and the congestion window -- are
// internal to the core and this module cannot import them.

// TestBrutalRunsOnShortPaths is E3. A congestion window of bps x RTT x 2 with
// no floor collapses to one or two datagrams when the round trip is a few
// hundred microseconds, which is what a same-datacenter deployment, a loopback
// test, and a candidate switch to a very close node all look like. Measured
// before the floor was added, the 1 MB/s declaration hung until the idle
// timeout on both attempts, 2 MB/s hung once and reached 47% the other time,
// and 8 MB/s reached 15-28%.
//
// The 64 MB/s row is the control: it passed before, because its window was
// already about 32 packets. It has to keep passing, or the floor has changed
// something other than the cases that were broken.
func TestBrutalRunsOnShortPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("four transfers, and the failure mode under test is an idle timeout")
	}
	profile := netem.Loss(0.05)
	for _, declared := range []uint64{1 << 20, 2 << 20, 8 << 20, 64 << 20} {
		declared := declared
		t.Run(metrics.FormatRate(float64(declared)), func(t *testing.T) {
			if declared >= 64<<20 && raceDetector {
				// Not a result about the controller: the bed itself cannot
				// carry this under the detector. Measured at 55% of the
				// declaration, against 93% without it.
				t.Skip("the impairment layer cannot supply 64 MB/s under -race")
			}
			// Scale the transfer with the declaration so that every row
			// measures a comparable stretch of steady state. Two megabytes at
			// 64 MB/s is thirty milliseconds, which is short enough that the
			// result is decided by where the first round trip sample happens to
			// land -- before it, the window is sized from quic-go's 100ms
			// default and is effectively unbounded; after it, from the real
			// path. Measured at 2MB, that row swung between 51% and 96% of the
			// declaration across five runs while the 1 and 2 MB/s rows, which
			// take a whole second, held at 92% every time.
			size := max(2<<20, int(declared/4))
			env := harness.New(t, harness.Options{
				Profile:        profile,
				Seed:           7,
				Bandwidth:      harness.Bandwidth{BytesPerSec: declared},
				MaxIdleTimeout: 4 * time.Second,
			})
			bps, err := env.TCPThroughput(size, 25*time.Second)
			require.NoError(t, err, "the transfer must complete: a window of one datagram stalls on every loss")
			t.Logf("declared %s: %s, %.0f%% of the declaration",
				metrics.FormatRate(float64(declared)), metrics.FormatRate(bps), bps/float64(declared)*100)
			assert.Greater(t, bps, 0.7*float64(declared),
				"a short path is not a reason to deliver less than the declared rate")
		})
	}
}

// TestBrutalSurvivesAPathDelayRise is the regression that decided how far the
// congestion window may follow the smoothed round trip.
//
// A window pinned to the path's lifetime minimum bounds in flight at
// 2 x bps x minRTT, which caps the achievable rate at 2 x bps x minRTT / R for
// a round trip of R. That is fine while R is the sender's own queue -- the
// point of the bound is to stop the sender inflating R -- and it is wrong when
// R rose for a reason the sender had nothing to do with: a reroute, congestion
// at the far end, a handover to a slower access network. The link below has
// eight times the declared rate to spare and nothing of ours can be queueing on
// it, and the round trip still triples. Measured with the window pinned to the
// minimum, goodput fell to 69.7% of the declared rate and stayed there; the
// arithmetic agrees, 2 x 20/60 = 0.67.
//
// The 3x rise is chosen because it is the edge of the envelope: with a clamp of
// K the sender stays rate-bound while the round trip is inside 2K x minRTT, so
// K = 2 tolerates 4x and is asserted at 3x with room to spare. A path that
// stretches further than that does lose rate, and that is the trade -- see
// docs/research/brutal.md section 3.2.
func TestBrutalSurvivesAPathDelayRise(t *testing.T) {
	if testing.Short() {
		t.Skip("two transfers, and the first one exists only to establish the path minimum")
	}
	const declared = 1 << 20
	const linkRate = 8 * declared // capacity to spare, so nothing here is a queue
	const shortRTT = 20 * time.Millisecond
	const longRTT = 3 * shortRTT

	base := netem.RateLimited(linkRate)
	env := harness.New(t, harness.Options{
		Profile:   base.WithRTT(shortRTT).Named("rate8MB/s+rtt20ms"),
		Seed:      7,
		Bandwidth: harness.Bandwidth{BytesPerSec: declared},
	})

	// The path minimum has to be the short path's, which is the whole premise:
	// a controller that never saw 20ms has nothing stale to be held back by.
	warm, err := env.TCPThroughput(1<<20, 30*time.Second)
	require.NoError(t, err)

	// The path itself gets longer. Same link, same rate, same buffer.
	env.Ctrl.Set(base.WithRTT(longRTT).Named("rate8MB/s+rtt60ms"))
	// Let the smoothed round trip find the new path before measuring: the
	// estimator is an EWMA, and the transfer would otherwise spend its first
	// stretch reporting the old path's figure.
	_, err = env.TCPLatency(20, 2, 20*time.Millisecond, 30*time.Second)
	require.NoError(t, err)

	bps, err := env.TCPThroughput(3<<20, 60*time.Second)
	require.NoError(t, err)
	t.Logf("declared %s: %s at a %v round trip, %s after it rose to %v (%.1f%% of the declaration)",
		metrics.FormatRate(declared), metrics.FormatRate(warm), shortRTT,
		metrics.FormatRate(bps), longRTT, bps/float64(declared)*100)

	assert.Greater(t, bps, 0.9*float64(declared),
		"a path whose own delay rose is not a queue this sender made, and must not cost it its declared rate")
}

// TestBrutalBlackholeRecovery is E8. While a path is blackholed the controller
// sees losses and no acknowledgements at all, which the ack ratio used to read
// as 100% loss and clamp to its floor -- so at the instant the path came back,
// it sent at 1.25x the declared rate, and kept doing so for as long as the
// five second sampling window took to refill. That is the worst moment to be
// over-sending: a path that has just returned is the least likely to have room,
// and a candidate that has just been switched to has no history at all.
//
// What is measured is bytes offered to the link, from the link's own counters,
// sampled every 200ms for several seconds after the blackhole lifts. The
// heaviest one-second window in there is the number: a single measurement of
// the first second says nothing, because the sender does not necessarily
// restart within it -- after seven seconds of blackhole the probe timer has
// backed off to seconds, and where the first packet lands inside the sampling
// interval is arbitrary.
func TestBrutalBlackholeRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the sampling window to fill, which takes longer than the window")
	}
	const linkRate = 1 << 20 // declared == capacity: any excess is the controller's doing
	const blackholeFor = 7 * time.Second
	const watchFor = 6 * time.Second
	const tick = 200 * time.Millisecond
	env := harness.New(t, harness.Options{
		Profile:   netem.RateLimited(linkRate).WithRTT(50 * time.Millisecond).Named("rate1MB/s+rtt50ms"),
		Seed:      7,
		Bandwidth: harness.Bandwidth{BytesPerSec: linkRate},
		// Long enough that the blackhole itself does not end the connection --
		// this is a test about what happens when it comes back.
		MaxIdleTimeout: 30 * time.Second,
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		env.TCPLoadFor(env.Client, 5*time.Second+blackholeFor+watchFor+2*time.Second)
	}()

	time.Sleep(4 * time.Second) // steady state before anything is broken
	env.Ctrl.SetBlackhole(true)
	time.Sleep(blackholeFor)
	env.Ctrl.SetBlackhole(false)

	samples := []uint64{env.Ctrl.Stats().Up.InBytes}
	for range int(watchFor / tick) {
		time.Sleep(tick)
		samples = append(samples, env.Ctrl.Stats().Up.InBytes)
	}
	wg.Wait()

	const window = int(time.Second / tick)
	var peak uint64
	for i := window; i < len(samples); i++ {
		if d := samples[i] - samples[i-window]; d > peak {
			peak = d
		}
	}
	total := samples[len(samples)-1] - samples[0]
	ratio := float64(peak) / linkRate
	t.Logf("after a %v blackhole: %d B offered over %v, heaviest second %d B = x%.3f the declared %s",
		blackholeFor, total, watchFor, peak, ratio, metrics.FormatRate(linkRate))

	require.NotZero(t, peak, "the flow never resumed, so there is nothing to measure")
	// The floor of the ack ratio is 0.8, so an over-send driven by it lands at
	// 1.25x. The bound is the one docs/research/brutal.md asks for -- 1.05x the
	// declared rate -- rather than something merely below 1.25: measured at
	// 1.037 and 1.036 across revisions, so a threshold set to just miss the
	// defect would leave 12 points of room in which the rule could come back
	// half-broken and still pass. What the remaining 5% covers is the
	// retransmission of what the blackhole swallowed, which is real work and is
	// not what this is about.
	assert.Less(t, ratio, 1.05,
		"a path with no acknowledgements at all is a path that is gone, not a path that is 100%% lossy")
}
