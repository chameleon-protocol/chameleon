package e2e

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/metrics"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// The end-to-end half of the acceptance criteria for the Brutal repairs.
// The rest are in the brutal package itself, because the two things that decide
// this controller's behaviour -- the ack rate and the congestion window -- are
// internal to the core and this module cannot import them.

// shortPathRefRTT is the path each row is compared against.
//
// It has to be long enough that the congestion window on it is set by the path
// and not by the floor, or the reference carries the same defect as the thing
// it is the reference for and the comparison says nothing. Thirty milliseconds
// is where that starts: the window is bps x RTT x 2, so at the lowest
// declaration on the ladder it is 60 KB, half again the 45 KB the floor asks
// for at the datagram size the bed negotiates (32 x ~1435). It is deliberately
// written here as a number rather than derived from the floor -- a reference
// computed from the constant under test would shrink with it, and the whole
// comparison would survive the constant's removal.
//
// It also has to be short enough that the impairment layer can still serve it.
// Delay in the bed is a scheduler, not a wire, and what it costs rises with the
// bandwidth-delay product: measured, the reference leg carries 84-90% of a
// 1 MB/s declaration and 29-59% of a 64 MB/s one, where the product is 1.9 MB.
const shortPathRefRTT = 30 * time.Millisecond

// shortPathRefFraction is how much of the declaration the reference leg must
// carry for the comparison below it to mean anything. A collapsed reference
// makes every ratio look good, which is how a relative assertion passes on
// broken code.
//
// Measured on the ladder rows over thirty container runs -- idle, with eight busy
// loops in a container alongside, with twenty-four, and with the floor removed,
// which does not reach a 30ms path -- and eighteen rows on the macOS host, the
// reference carried between 61% and 90% of its declaration. 0.45 is a quarter
// below the worst of that, which leaves room for a slower host, and is still an
// order of magnitude above what a starved bed produces: 200 busy loops
// in-container calibrate the bed at 3.8 MB/s.
//
// It bounds how vacuous the comparison can get; it does not bound throughput,
// and is not meant to. A regression that cost both legs the same would pass
// here, and this is a test about the difference between two paths.
const shortPathRefFraction = 0.45

// shortPathFraction is how far behind the reference the short path may fall.
//
// Measured with the floor in place, the ladder rows came out between 0.93 and
// 1.27 times their reference: minimum 0.937 over sixty-six rows in twenty-two
// container runs -- idle, under eight busy loops and under twenty-four -- and
// 0.934 over eighteen rows on the macOS host, whose loopback is quicker and
// whose reference is correspondingly closer. With cwndFloorPackets cut to 1 they
// landed between 0.585 and 0.830 on all thirty measurements, and every run
// failed.
//
// 0.88 is the middle of that gap, 6% clear on each side. That 6% is a row's
// margin, not the test's: a broken run has three rows to be caught by and needs
// only one of them, and no run has ever been caught by fewer than all three.
const shortPathFraction = 0.88

// TestBrutalRunsOnShortPaths is E3: a short path is not a reason to deliver
// less. A congestion window of bps x RTT x 2 with no floor collapses to one or
// two datagrams when the round trip is a few hundred microseconds, which is
// what a same-datacenter deployment, a loopback test, and a candidate switch to
// a very close node all look like.
//
// Each row therefore measures one declaration twice, back to back on the same
// host: once over shortPathRefRTT and once over loopback. The claim is a
// comparison between two paths, so the assertion is one too. A fraction of the
// declaration is not, and cannot be made into one:
//
// What this bed delivers at a fixed declaration is set by the pacer's burst cap
// and by how often the container's send loop gets to run, not by the path. The
// cap is max(2ms x bps, 10 datagrams), in the pacer the core installs under this
// controller, so a send loop that wakes every few milliseconds can only ever
// emit one cap per wake.
// Measured, with nothing else changed, raising that multiplier from 2 to 16
// moved an 8 MB/s declaration from 65% to 94% of the declaration and a 64 MB/s
// one from 75% to 92%. It is the same story from the other end: the 8 MB/s
// declaration reads 65.6%, 60.3% and 59.9% at round trips of 0, 5 and 20 ms. A
// shortfall that does not move when the path length changes by three orders of
// magnitude is not a short-path problem, and a short-path problem is the only
// thing this test claims to measure. The "bps > 0.7 x declared" this replaces
// was reading the host's timer granularity: measured sixteen times in this
// container, that row cleared 70% once, and the same row on the macOS host reads
// 91.7% and 92.6%.
//
// The ladder is the declarations whose window the floor is what saves. The
// window is sized from max(smoothed RTT, 1ms) -- quic-go's pacing granularity,
// below which the round trip describes the scheduler rather than the path -- so
// on loopback it is 2 x bps x 1ms: 1.5, 2.9 and 5.8 datagrams at 1, 2 and 4
// MB/s, against the 32 the floor asks for.
//
// 8 MB/s was on this ladder and is not any more. At 8 MB/s the burst cap above
// has overtaken the ten datagrams it is the maximum of (2ms x 8 MB/s is 16 KB
// against 10 x ~1435), so the cap binds before the window does and the row
// measures the wake period instead. It shows: with the floor removed the three
// remaining rows land at 0.585-0.830 of their reference, while 8 MB/s came back
// at 0.766, 0.938 and 0.981 -- it would have reported the floor intact on two
// runs out of three. The row had stopped discriminating; keeping it would have
// been three seconds spent asserting the host was not busy.
//
// controlMinReference is the least the control row's reference leg may carry
// before its ratio stops meaning anything. Written out rather than derived from
// the declaration: the declaration is unreachable on every bed measured here,
// which is the whole reason this row is exempt from the fraction the ladder
// rows use.
const controlMinReference = 500 << 10

// 64 MB/s is the control. Its window on loopback is 93 datagrams before any
// floor applies, so the floor cannot be what carries it, and it has to keep
// passing or the floor has changed a case that was not broken. It is the one
// row without the reference-fraction assertion, because there is no declaration
// that both clears the floor and stays inside what every bed can carry: the
// window only clears 32 datagrams above about 23 MB/s, and the macOS loopback
// bed saturates around 10 MB/s whatever is declared (measured, at declarations
// of 16, 24, 32, 48 and 64 MB/s it returned 8.2, 4.4, 9.9, 10.4 and 10.3 MB/s).
// A fraction-of-declaration floor on this row would be an assertion about the
// host's socket throughput. What is left on it is the comparison, which is what
// the row is for. It can pass vacuously if the bed collapses on both legs at
// once, and that is the price of having a control row at all.
//
// Every row measures both of its own legs, so each of these assertions holds
// when the row is run alone under a -run filter.
func TestBrutalRunsOnShortPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("eight transfers, and the failure mode under test is an idle timeout")
	}
	for _, row := range []struct {
		declared uint64
		// control marks the row the floor never reaches, which is therefore
		// also the row no bed can be held to a fraction of.
		control bool
	}{
		{declared: 1 << 20},
		{declared: 2 << 20},
		{declared: 4 << 20},
		{declared: 64 << 20, control: true},
	} {
		t.Run(metrics.FormatRate(float64(row.declared)), func(t *testing.T) {
			// One second of the declaration on each leg. The shortfall being
			// measured is a rate and not a startup cost -- at 8 MB/s the same
			// figure comes back at 65%, 67%, 65% and 65% for transfers of 1, 4,
			// 16 and 32 MB -- but a leg has to outlast the first round trip
			// sample all the same: before it, the window is sized from quic-go's
			// 100ms default and is effectively unbounded.
			//
			// The cap is for the bed rather than the controller. A second of a
			// 64 MB/s declaration is 64 MB, and a bed that carries 4.7 MB/s of
			// it -- the macOS host's figure on the reference path -- would spend
			// fourteen seconds on that one leg, most of the transfer deadline.
			// Half of it is still two thirds of a second of steady state
			// wherever the bed does keep up.
			size := min(int(row.declared), 32<<20)
			reference := shortPathLeg(t, row.declared, shortPathRefRTT, size)
			shortPath := shortPathLeg(t, row.declared, 0, size)
			t.Logf("declared %s: %s over a %v path, %s over loopback -- %.0f%% and %.0f%% of the declaration, ratio %.3f",
				metrics.FormatRate(float64(row.declared)), metrics.FormatRate(reference), shortPathRefRTT,
				metrics.FormatRate(shortPath), reference/float64(row.declared)*100,
				shortPath/float64(row.declared)*100, shortPath/reference)

			if row.control {
				// The control row cannot use a fraction of its declaration: no
				// bed here carries 64 MB/s, and the macOS loopback saturates
				// near 10. What it can require is that the reference leg moved
				// enough to be a measurement at all, so that a bed collapsing
				// on both legs at once fails the row instead of passing it with
				// a ratio of one. The bound is an order of magnitude below the
				// slowest bed measured (4.4 MB/s on the macOS host), because it
				// is guarding against collapse, not grading the bed.
				assert.Greater(t, reference, float64(controlMinReference),
					"the reference leg carried %s, too little for the ratio below to mean anything",
					metrics.FormatRate(reference))
			} else {
				assert.Greater(t, reference, shortPathRefFraction*float64(row.declared),
					"the reference path carried too little to be a reference: this is the bed failing, not the controller")
			}
			assert.GreaterOrEqual(t, shortPath, shortPathFraction*reference,
				"the same declaration delivered less over loopback than over a %v path: a short path is not a reason to deliver less", shortPathRefRTT)
		})
	}
}

// shortPathLeg is one declaration measured over one path length.
func shortPathLeg(t *testing.T, declared uint64, rtt time.Duration, size int) float64 {
	t.Helper()
	profile := netem.Loss(0.05).WithRTT(rtt).Named(fmt.Sprintf("loss5%%+rtt%v", rtt))
	env := harness.New(t, harness.Options{
		Profile:   profile,
		Seed:      7,
		Bandwidth: harness.Bandwidth{BytesPerSec: declared},
		// The failure mode this test was written for is a window of one
		// datagram stalling on every loss until the connection times out, so
		// the timeout has to be short enough to be reached inside the
		// transfer's own deadline. Four seconds is the minimum the core
		// accepts.
		//
		// It is kept as a guard rather than as the thing being measured. Since
		// windowRTT gained its one millisecond floor, removing cwndFloorPackets
		// no longer hangs anything: measured over thirty rows with the floor
		// cut to 1, every transfer completed, the worst of them at 46% of the
		// declaration. What is left of the defect is a rate, which is what the
		// comparison below measures.
		MaxIdleTimeout: 4 * time.Second,
	})
	bps, err := env.TCPThroughput(size, 25*time.Second)
	require.NoError(t, err, "the transfer must complete: a window of one datagram stalls on every loss")
	return bps
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
// stretches further than that does lose rate, and that is the trade.
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
// interval is arbitrary. That is why the design document's "the first second
// after recovery" is not what is measured here; see its E8 entry.
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

	// Each sample carries the clock reading that produced it. Counting a fixed
	// number of ticks as "a second" would be a measurement of the host's
	// scheduler as much as of the sender: five sleeps of 200ms are 1.0s on an
	// idle machine and 1.25s on a busy one, and dividing 1.25s of bytes by one
	// second reports a 25% over-send that never happened.
	type sample struct {
		at    time.Time
		bytes uint64
	}
	samples := []sample{{time.Now(), env.Ctrl.Stats().Up.InBytes}}
	for range int(watchFor / tick) {
		time.Sleep(tick)
		samples = append(samples, sample{time.Now(), env.Ctrl.Stats().Up.InBytes})
	}
	wg.Wait()

	// The heaviest rate over any window of at least a second, taking the
	// shortest such window from each starting point: longer ones only average
	// the burst away, and the burst is what is being bounded.
	var peak float64
	for i := range samples {
		for j := i + 1; j < len(samples); j++ {
			d := samples[j].at.Sub(samples[i].at)
			if d < time.Second {
				continue
			}
			if r := float64(samples[j].bytes-samples[i].bytes) / d.Seconds(); r > peak {
				peak = r
			}
			break
		}
	}
	total := samples[len(samples)-1].bytes - samples[0].bytes
	ratio := peak / linkRate
	t.Logf("after a %v blackhole: %d B offered over %v, heaviest second %s = x%.3f the declared %s",
		blackholeFor, total, watchFor, metrics.FormatRate(peak), ratio, metrics.FormatRate(linkRate))

	require.NotZero(t, peak, "the flow never resumed, so there is nothing to measure")
	// The floor of the ack ratio is 0.8, so an over-send driven by it lands at
	// 1.25x, and the bound wants to be far enough below that to catch the rule
	// coming back half-broken rather than merely to miss the defect.
	//
	// The design document asks for 1.05x. That figure was measured against a
	// window pinned to the path minimum; with the window clamped at twice it
	// (cwndRTTClampK), recovery releases twice the flight, because seven
	// seconds of blackhole leaves the smoothed round trip inflated by the
	// late-acked probes and the clamp is what the window then sits on.
	// Measured over five runs here: 1.016, 1.034, 1.041, 1.043, 1.053 -- so
	// 1.05 sits inside the spread and would fail about one run in five. The
	// bound is therefore 1.08, which is the observed maximum plus the same
	// margin again, still 17 points below the defect, and still a tightening of
	// the 1.15 it replaces. The deviation from the document is recorded in its
	// E8 entry rather than left as a silent loosening.
	//
	// What the allowance covers is the retransmission of what the blackhole
	// swallowed, which is real work and is not what this is about.
	assert.Less(t, ratio, 1.08,
		"a path with no acknowledgements at all is a path that is gone, not a path that is 100%% lossy")
}
