package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// What a blocked path looks like from inside the endpoint, and how fast it can
// be told from a path that is merely bad.
//
// The Selector has to decide "this path is dead, switch", and that decision
// needs a detector. This file is the measurement the detector rests on: it puts
// a live connection under load, breaks the link in one specific way, and
// records what the only health surface the core exposes -- the
// client.PathStatsProvider interface, i.e. quic-go's ConnectionStats -- did
// afterwards. netem's own counters appear only as proof that the fault
// happened; nothing in a Signature comes from them.
//
// The numbers are in the findings block at the bottom of the file. Read them
// before changing any threshold here.

// pathfailBase is the condition every scenario starts from, so that the
// RTT-step case is a change from the same place as the others.
func pathfailBase() netem.Profile { return netem.RTT(50 * time.Millisecond) }

// pathfailOpts keeps the idle timeout at the minimum the core accepts, so that
// the stack's own verdict lands inside a short observation instead of half a
// minute later. The production default is 30s; see the findings for what that
// does to the comparison.
func pathfailOpts(seed uint64) harness.Options {
	return harness.Options{
		Profile:         pathfailBase(),
		Seed:            seed,
		MaxIdleTimeout:  4 * time.Second,
		KeepAlivePeriod: 2 * time.Second,
	}
}

func brutalOpts(seed uint64) harness.Options {
	o := pathfailOpts(seed)
	o.Bandwidth = harness.Bandwidth{BytesPerSec: 4 << 20}
	return o
}

const (
	pathfailFaultAt  = 3 * time.Second
	pathfailDuration = 12 * time.Second
)

// interactive is the load a censored user's shell or web session looks like:
// one small exchange every 50ms, so the connection is nearly idle when the
// fault lands and the receive side has natural gaps of about one RTT plus the
// pause. That noise floor is the reason a silence threshold cannot be small.
func interactive(fault netem.Profile) harness.Observation {
	return harness.Observation{
		Gap:             50 * time.Millisecond,
		Payload:         100,
		ExchangeTimeout: 2 * time.Second,
		Sample:          20 * time.Millisecond,
		Duration:        pathfailDuration,
		FaultAt:         pathfailFaultAt,
		Fault:           fault,
	}
}

// bulk keeps the pipe full in both directions, so the peer has unacked data at
// the moment of the cut. That is the only state in which the two one-way
// failures could look different from each other or from a full blackhole.
func bulk(fault netem.Profile) harness.Observation {
	o := interactive(fault)
	o.Bulk = true
	return o
}

type pathfailCase struct {
	name  string
	fault netem.Profile
	obs   func(netem.Profile) harness.Observation
	opts  func(uint64) harness.Options
}

func pathfailCases() []pathfailCase {
	base := pathfailBase()
	return []pathfailCase{
		// The control. Without it there is no noise floor, and every gap in the
		// counters looks like a signal.
		{"none", base.Named("none"), interactive, pathfailOpts},
		{"blackhole", base.WithBlackhole(true).Named("blackhole"), interactive, pathfailOpts},
		{"loss30%", base.WithLoss(0.30).Named("loss30%"), interactive, pathfailOpts},

		// A reroute, not a block. This is the case a naive detector switches on
		// and should not.
		{"rtt-step-200ms", netem.RTT(200 * time.Millisecond).Named("rtt-step-200ms"), interactive, pathfailOpts},
		{"rtt-step-400ms", netem.RTT(400 * time.Millisecond).Named("rtt-step-400ms"), interactive, pathfailOpts},
		{"rtt-step-1s", netem.RTT(time.Second).Named("rtt-step-1s"), interactive, pathfailOpts},

		{"up-dead", base.WithUpBlackhole(true).Named("up-dead"), interactive, pathfailOpts},
		{"down-dead", base.WithDownBlackhole(true).Named("down-dead"), interactive, pathfailOpts},

		{"blackhole-bulk", base.WithBlackhole(true).Named("blackhole-bulk"), bulk, pathfailOpts},
		{"up-dead-bulk", base.WithUpBlackhole(true).Named("up-dead-bulk"), bulk, pathfailOpts},
		{"down-dead-bulk", base.WithDownBlackhole(true).Named("down-dead-bulk"), bulk, pathfailOpts},

		// Brutal paces at a declared rate and ignores loss by construction, so
		// it is the controller for which "the sender backed off" cannot be a
		// detector. Both Brutal rows exist to be compared against their BBR
		// twins above.
		{"blackhole-brutal", base.WithBlackhole(true).Named("blackhole-brutal"), bulk, brutalOpts},
		{"loss30%-brutal", base.WithLoss(0.30).Named("loss30%-brutal"), bulk, brutalOpts},
	}
}

// silenceThresholds is the sweep. A receive-silence detector has exactly one
// parameter, so the honest way to choose it is to run every failure mode
// against every candidate value and read off which values separate them.
var silenceThresholds = []time.Duration{
	100 * time.Millisecond,
	200 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
}

// BenchmarkPathFailureSignatures prints the table the findings below are read
// from. It is a benchmark rather than a test because it asserts nothing: it is
// the measurement, and the claims taken from it are held by the tests that
// follow.
//
//	go test ./e2e/ -run '^$' -bench PathFailureSignatures -benchtime 1x -v
func BenchmarkPathFailureSignatures(b *testing.B) {
	for i, c := range pathfailCases() {
		b.Run(c.name, func(b *testing.B) {
			for range b.N {
				env := harness.New(b, c.opts(uint64(100+i)))
				rep := env.Observe(c.obs(c.fault))
				env.Close()
				upIn, upOut, downIn, downOut := rep.Delivered()
				b.Logf("%-16s %s", c.name, rep.Signature())
				b.Logf("%-16s ground truth after settle: up offered=%d delivered=%d | down offered=%d delivered=%d",
					c.name, upIn, upOut, downIn, downOut)
				for _, s := range silenceThresholds {
					b.Logf("%-16s silence>=%-6s fires at %-8s (false alarm before the fault: %s)",
						c.name, s, fmtNever(rep.DetectAt(s)), fmtNever(rep.FalseDetect(s)))
				}
			}
		})
	}
}

func fmtNever(d time.Duration) string {
	if d == harness.Never {
		return "never"
	}
	return d.Round(time.Millisecond).String()
}

// selectorSilence is the threshold the measurements support, and the only
// number in this file a Selector should copy.
//
// It is not a round number chosen for looks. Over twelve observations of links
// that were still working, the largest gap between packets received was 1.402s
// (30% loss, one run in five; the other four gave 440ms to 619ms). Over eight
// observations of links that were dead, the slowest a 2s detector fired was
// 5.803s, and it fired on every one. 2s is the only value on the sweep grid
// that never fired on a working link and always fired on a dead one.
//
// The margin below is thin and honestly so: 1.4x, on a tail set by loss rather
// than by anything structural. That is the measurement's real message. It says
// a 2s detection is a reason to go and probe another candidate, not a reason to
// move a live connection on its own -- and the design already has the probe.
const selectorSilence = 2 * time.Second

// longObs gives nine seconds after the fault. up-dead is the reason: the server
// goes on retransmitting into the void for seconds, so the detector's slowest
// measured firing was 5.803s and a shorter window would score that as "never".
func longObs(o harness.Observation) harness.Observation {
	o.FaultAt = 2 * time.Second
	o.Duration = 11 * time.Second
	return o
}

// TestReceiveSilenceSeparatesDeadPathsFromBadOnes is the recommendation held as
// an assertion.
//
// A detector that watches one number -- how long since PacketsReceived last
// increased -- fires on every path that was blackholed in any direction, and
// stays silent on paths that are merely lossy, merely slow, or merely rerouted.
// Nothing else in pathstats.Stats does this; see the findings.
func TestReceiveSilenceSeparatesDeadPathsFromBadOnes(t *testing.T) {
	if testing.Short() {
		t.Skip("each case runs a live connection for eleven seconds")
	}
	base := pathfailBase()
	cases := []struct {
		name  string
		fault netem.Profile
		dead  bool
	}{
		{"none", base.Named("none"), false},
		{"loss30%", base.WithLoss(0.30).Named("loss30%"), false},
		{"rtt-step-1s", netem.RTT(time.Second).Named("rtt-step-1s"), false},
		{"blackhole", base.WithBlackhole(true).Named("blackhole"), true},
		{"up-dead", base.WithUpBlackhole(true).Named("up-dead"), true},
		{"down-dead", base.WithDownBlackhole(true).Named("down-dead"), true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := harness.New(t, pathfailOpts(uint64(200+i)))
			rep := env.Observe(longObs(interactive(c.fault)))
			sig := rep.Signature()
			fired := rep.DetectAt(selectorSilence)
			t.Logf("%s: %s", c.name, sig)
			t.Logf("%s: silence>=%s fires at %s", c.name, selectorSilence, fmtNever(fired))

			// Ground truth, from netem's own counters: the link did what the
			// profile said. Without this a case that silently failed to impair
			// anything would look like a passing assertion.
			upOffered, upOut, downOffered, downOut := rep.Delivered()
			t.Logf("%s: netem after settle: up delivered %d of %d offered, down delivered %d of %d",
				c.name, upOut, upOffered, downOut, downOffered)
			if c.dead {
				require.Zero(t, upOut*downOut, "a blackholed direction still delivered")
			} else {
				require.Positive(t, downOut, "the link delivered nothing; the case did not run")
			}

			if c.dead {
				require.NotEqual(t, harness.Never, fired, "a dead path was never detected")
				// Measured worst over eight dead observations: 5.803s (up-dead,
				// which has to outlast the peer's own retransmissions). The
				// bound is above that and below the nine seconds of window, so
				// it fails rather than silently reading "never".
				assert.Less(t, fired, 8*time.Second, "detection was slower than every run measured")
				return
			}
			assert.Equal(t, harness.Never, fired,
				"a working path was declared dead; the threshold is below this link's noise floor")
			assert.Positive(t, sig.RxAfter, "a working path delivered no packets to the stack")
			assert.Equal(t, harness.Never, sig.GoneAt, "the connection did not survive")
		})
	}
}

// TestNaiveSilenceThresholdsSwitchOnAWorkingPath is the negative result, and
// the reason selectorSilence is 2s rather than the 200ms a design would reach
// for.
//
// The gap between packets on a healthy interactive flow is one RTT plus the
// application's own pause. On a path that has just rerouted onto a slower one
// that gap is a second, and it is a second before any evidence of the reroute
// can exist -- the evidence has to travel the new path. Every threshold short
// enough to be called fast fires here, on a path where switching is strictly
// worse than staying.
func TestNaiveSilenceThresholdsSwitchOnAWorkingPath(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live connection for eleven seconds")
	}
	env := harness.New(t, pathfailOpts(300))
	rep := env.Observe(longObs(interactive(netem.RTT(time.Second).Named("rtt-step-1s"))))
	sig := rep.Signature()
	t.Logf("rtt-step-1s: %s", sig)

	// The path is unquestionably alive: still delivering, and the application
	// never saw a failure.
	_, _, _, downOut := rep.Delivered()
	require.Positive(t, downOut)
	require.Positive(t, sig.RxAfter)
	require.Equal(t, harness.Never, sig.GoneAt)

	for _, s := range []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, selectorSilence} {
		t.Logf("silence>=%-6s on a rerouted but working path fires at %s", s, fmtNever(rep.DetectAt(s)))
	}

	// Only the 200ms claim is asserted. The measured gaps on this case run from
	// 560ms to 1.062s -- a run where the stale PTO storms out extra packets has
	// smaller gaps than one where it does not -- so 200ms clears every run by
	// 2.8x, while 500ms and 1s fired in every run observed but with margins too
	// small to hold. The claim that matters is the one 200ms carries: a
	// threshold fast enough to be attractive fires on a path where switching is
	// strictly worse than staying.
	assert.NotEqual(t, harness.Never, rep.DetectAt(200*time.Millisecond),
		"a 200ms threshold did not fire on a 1s reroute; the reroute is not being modelled")
	assert.Equal(t, harness.Never, rep.DetectAt(selectorSilence),
		"the recommended threshold fired on a rerouted but working path")
}

// TestRTTFreshnessIsNotALivenessSignal kills the obvious second signal.
//
// The natural way to exculpate a reroute is "an ack came back, so the path is
// alive": watch LatestRTT for a new sample and treat one as proof of life. It
// cannot work, because the rate at which RTT samples arrive is 1/RTT. A healthy
// 50ms path produced 85-87 samples in nine seconds. The same path after a step
// to 1s produced 0 to 8, measured over five runs. A blackholed path produced 0
// to 2. The rerouted case and the dead case land in the same band, and in one
// Linux run of five the rerouted path produced exactly zero -- so no threshold
// on sample count or sample freshness separates them.
//
// The zero runs are worth naming: quic-go takes an RTT sample only when the
// ack's largest-acked packet was sent no earlier than the previously
// largest-acked one (internal/ackhandler/sent_packet_handler.go, the
// largestAckedTime guard), and a twentyfold step makes the PTO -- computed from
// the stale estimate -- fire repeatedly before any ack can arrive. That is a
// consistent explanation, not a verified one, and it is not deterministic: the
// same case on macOS tracked the step to 677ms. The overlap below is the part
// that reproduces everywhere.
func TestRTTFreshnessIsNotALivenessSignal(t *testing.T) {
	if testing.Short() {
		t.Skip("three live connections for eleven seconds each")
	}
	base := pathfailBase()
	fresh := func(seed uint64, fault netem.Profile) harness.Signature {
		env := harness.New(t, pathfailOpts(seed))
		defer env.Close()
		sig := env.Observe(longObs(interactive(fault))).Signature()
		t.Logf("%-12s fresh RTT samples=%-4d srtt %s -> %s, minrtt %s -> %s, received after the fault=%d",
			fault.Name, sig.FreshRTT, sig.SRTTBefore, sig.SRTTAfter,
			sig.MinRTTBefore, sig.MinRTTAfter, sig.RxAfter)
		return sig
	}
	healthy := fresh(304, base.Named("none"))
	rerouted := fresh(305, netem.RTT(time.Second).Named("rtt-step-1s"))
	dead := fresh(306, base.WithBlackhole(true).Named("blackhole"))

	require.Positive(t, rerouted.RxAfter,
		"nothing arrived on the rerouted path, so it is not alive and there is no overlap to show")

	// The bounds sit either side of the gap between "many" and "few", far from
	// every value measured: healthy 85-87, rerouted 0-8, dead 0-2.
	assert.Greater(t, healthy.FreshRTT, 40, "a healthy 50ms path stopped producing RTT samples")
	assert.Less(t, rerouted.FreshRTT, 20,
		"the rerouted path produced samples at a healthy rate; the 1/RTT argument is wrong")
	assert.Less(t, dead.FreshRTT, 20)
	// The overlap itself, which is the finding: any threshold that calls the
	// rerouted path alive also calls the dead path alive.
	assert.LessOrEqual(t, dead.FreshRTT, rerouted.FreshRTT+8,
		"the dead path and the rerouted path separated; RTT freshness may be usable after all")

	// MinRTT is a running minimum and cannot rise, so the documented reading of
	// SmoothedRTT-MinRTT as "the bufferbloat on this path" is wrong for the rest
	// of the connection's life after any reroute.
	assert.LessOrEqual(t, rerouted.MinRTTAfter, rerouted.MinRTTBefore, "MinRTT rose, which it cannot")
}

// TestDeadPathIsVisibleLongBeforeTheStackSaysSo is why the Selector needs a
// detector of its own rather than an error to react to.
//
// The stack's verdict is the QUIC idle timeout, and the application only learns
// it when a call that had no deadline finally returns. This runs with the idle
// timeout at 4s, the minimum the core accepts; the production default is 30s,
// so the gap measured here is the smallest it can ever be.
func TestDeadPathIsVisibleLongBeforeTheStackSaysSo(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the QUIC idle timeout to expire")
	}
	env := harness.New(t, pathfailOpts(301))
	rep := env.Observe(interactive(pathfailBase().WithBlackhole(true).Named("blackhole")))
	sig := rep.Signature()
	fired := rep.DetectAt(selectorSilence)
	t.Logf("blackhole: %s", sig)
	t.Logf("blackhole: silence>=%s fires at %s, the application learned the connection was gone at %s",
		selectorSilence, fmtNever(fired), fmtNever(sig.GoneAt))

	_, upOut, _, downOut := rep.Delivered()
	require.Zero(t, upOut+downOut, "the blackhole delivered something")
	require.NotEqual(t, harness.Never, sig.GoneAt, "the stack never gave up inside the window")
	require.NotEqual(t, harness.Never, fired)

	// Measured: fired at 2.017s, application told at 4.998s. The two bounds are
	// separate claims rather than a ratio: the detector is quick (2.02s
	// measured, 3s asserted), and the stack cannot be quicker than the idle
	// timeout it is waiting out.
	assert.Less(t, fired, 3*time.Second, "the detector was slower than every run measured")
	assert.Greater(t, sig.GoneAt, 4*time.Second,
		"the stack reported the loss faster than its own idle timeout, which it cannot")
}

// TestPathStatsSurvivesTheConnectionItDescribes records a trap in the only API
// a Selector has.
//
// PathStats returns (stats, true) forever. A plain client hands back a
// pathstats.Stats read from a *quic.Conn that has already closed, with every
// counter frozen at its last value: no ok=false, no error, no field that says
// dead. "The numbers stopped moving" is the only form in which death reaches a
// caller, which is the same form a blackhole takes -- so the detector this file
// recommends covers both, and a Selector that polls and waits to be told covers
// neither.
func TestPathStatsSurvivesTheConnectionItDescribes(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the QUIC idle timeout to expire")
	}
	env := harness.New(t, pathfailOpts(302))
	rep := env.Observe(interactive(pathfailBase().WithBlackhole(true).Named("blackhole")))
	sig := rep.Signature()

	require.NotEqual(t, harness.Never, sig.GoneAt, "the connection did not die, so there is nothing to check")
	assert.Equal(t, harness.Never, sig.OKFalseAt,
		"PathStats reported that it had no connection; if that is now true the API has grown a liveness signal")

	var afterDeath []harness.PathSample
	for _, s := range rep.Samples {
		if s.At-rep.FaultAt >= sig.GoneAt {
			afterDeath = append(afterDeath, s)
		}
	}
	require.NotEmpty(t, afterDeath, "no samples were taken after the connection died")
	first, last := afterDeath[0], afterDeath[len(afterDeath)-1]
	t.Logf("after death (%d samples over %s): sent %d->%d received %d->%d srtt %s->%s",
		len(afterDeath), (last.At - first.At).Round(time.Millisecond),
		first.Stats.PacketsSent, last.Stats.PacketsSent,
		first.Stats.PacketsReceived, last.Stats.PacketsReceived,
		first.Stats.SmoothedRTT, last.Stats.SmoothedRTT)
	assert.True(t, last.OK, "PathStats stopped answering")
	assert.Equal(t, first.Stats, last.Stats, "a closed connection's counters moved")
}

// TestPacketsLostIsNeverPopulated is the API gap that matters most, because
// keying the stay-or-switch decision on a loss rate is the obvious design and
// it cannot be built.
//
// quic-go increments ConnectionStats.PacketsLost in exactly one place --
// internal/congestion/cubic_sender.go, in OnPacketLost -- and chameleon never
// runs cubic: core/client replaces the controller with BBR or Brutal through
// SetCongestionControl as soon as authentication finishes. So
// pathstats.Stats.PacketsLost, BytesLost, and the LossRate() derived from them
// are zero for the whole life of every connection this project makes, on every
// path, under every impairment.
//
// The check drops a third of the datagrams in both directions and confirms the
// counter does not move while the counters either side of it do.
func TestPacketsLostIsNeverPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live connection for eleven seconds")
	}
	env := harness.New(t, brutalOpts(303))
	rep := env.Observe(longObs(bulk(pathfailBase().WithLoss(0.30).Named("loss30%"))))
	sig := rep.Signature()

	// Ground truth: the link really did lose a large fraction of what it was
	// given, in both directions.
	upIn, upOut, downIn, downOut := rep.Delivered()
	require.Positive(t, upIn)
	require.Positive(t, downIn)
	upLoss := 1 - float64(upOut)/float64(upIn)
	downLoss := 1 - float64(downOut)/float64(downIn)
	t.Logf("netem delivered %d of %d offered up (%.1f%% dropped) and %d of %d down (%.1f%% dropped)",
		upOut, upIn, upLoss*100, downOut, downIn, downLoss*100)
	require.Greater(t, upLoss, 0.2, "the link was not actually lossy")
	require.Greater(t, downLoss, 0.2, "the link was not actually lossy")

	// The neighbouring counters move, so the struct is live and being read and
	// the zero below is a fact about the field rather than about the test.
	require.Positive(t, sig.TxAfter, "PacketsSent did not move")
	require.Positive(t, sig.RxAfter, "PacketsReceived did not move")

	last := rep.Samples[len(rep.Samples)-1].Stats
	t.Logf("pathstats under that loss: sent=%d received=%d lost=%d loss-rate=%v",
		last.PacketsSent, last.PacketsReceived, last.PacketsLost, last.LossRate())
	assert.Zero(t, last.PacketsLost,
		"PacketsLost moved; cubic may be back in the path, and the loss signal is usable after all")
	assert.Zero(t, last.BytesLost, "BytesLost moved")
	assert.Zero(t, last.LossRate(), "LossRate moved")
	assert.Zero(t, sig.LostDelta)
	assert.Zero(t, sig.LostStepMin)
}

// THE FINDINGS.
//
// From BenchmarkPathFailureSignatures, Linux in the container, 50ms RTT
// baseline, fault at 3s, observed for 9s after it, QUIC idle timeout 4s,
// keep-alive 2s. Every duration is measured from the fault. rx-gap-max is the
// longest run with no increase in PacketsReceived; fresh-rtt is the number of
// samples in which LatestRTT changed; app-gone is when the application first
// learned the connection was finished.
//
//	case              rx-gap-max  fresh-rtt  tx-after  tx-span  app-gone
//	loss30%-brutal          39ms        449     30069   8.998s     never
//	none                   123ms         85       172   8.981s     never
//	rtt-step-200ms         280ms         34        81   8.859s     never
//	rtt-step-400ms         462ms         19        47   8.921s     never
//	loss30%                939ms         36       147   8.980s     never
//	rtt-step-1s           1.019s          0       179   8.961s     never
//	up-dead-bulk          6.343s          2      3276   7.379s    9.659s
//	up-dead               6.241s          1        22   7.380s    8.419s
//	down-dead-bulk        8.940s          0      1886   5.980s    7.027s
//	blackhole-bulk        8.959s          0      1270   6.099s    7.024s
//	blackhole-brutal      8.962s          1       258   2.660s    5.030s
//	blackhole             8.999s          0        12   3.337s    4.998s
//	down-dead             9.002s          0        12   3.319s    4.990s
//
// Five repeats of the three cases that decide the threshold, same setup:
//
//	loss30%      rx-gap-max  440ms  463ms  602ms  619ms  1.402s
//	rtt-step-1s  rx-gap-max  1.017s 1.060s 1.060s 1.061s 1.062s
//	up-dead      rx-gap-max  5.198s 6.342s 6.359s 8.981s 8.998s
//	up-dead      2s detector fires at  1.978s 1.999s 4.643s 4.657s 5.803s
//
// 1. RECEIVE SILENCE IS THE SIGNAL, AND IT IS THE ONLY ONE.
//
// The longest gap between packets received on a link that still worked was
// 1.402s. The shortest on a link that was dead was 5.198s. Nothing else in
// pathstats.Stats separates the two sets, and the fields that look like they
// should are worse than useless:
//
//   - SmoothedRTT does not rise on a dead path -- it freezes, because an
//     estimate only moves when an ack arrives. So "SmoothedRTT is still small"
//     is true of a healthy path and of a dead one alike, and reading it as
//     health is reading a stale number.
//   - The rate at which new RTT samples arrive is 1/RTT, so it collapses on any
//     slow path as well as on a dead one: 85-87 samples in nine seconds on a
//     healthy 50ms link, 0-8 after a step to 1s, 0-2 when blackholed. The last
//     two overlap, which is finding 3.
//   - MinRTT is a running minimum and cannot rise at all. After a reroute the
//     documented reading of SmoothedRTT-MinRTT as this path's bufferbloat is
//     simply wrong for the rest of the connection.
//   - PacketsLost, BytesLost and LossRate are always zero (finding 6).
//   - PacketsSent says what the congestion controller did (finding 2).
//
// A detector is one subtraction on one counter: how long since PacketsReceived
// last increased. selectorSilence holds the value, 2s, and its comment holds
// the margins.
//
// One property of that counter is worth having on purpose rather than by
// accident, and it is the reason to prefer it over a counter taken at the
// socket. quic-go increments PacketsReceived in
// sentPacketHandler.ReceivedPacket, which connection.go calls only after the
// packet has been unpacked and its frames handled -- so it counts authenticated
// packets, not datagrams. (ConnectionStats' own doc comment says "including
// packets that were not processable"; for this counter it is wrong.) An on-path
// attacker who blackholes the server cannot keep the detector quiet by
// injecting traffic at us: forged datagrams fail AEAD, never reach the ack
// handler, and never move the number. A detector reading the netem-style
// datagram counters, or anything else at the socket, would not have that.
//
// 2. THE SEND SIDE SAYS NOTHING ABOUT THE PATH.
//
// Into an identical blackhole under an identical bulk load, BBR put 1270
// packets on the wire and Brutal 258 -- and on a second run of the same two
// cells, 2211 and 246. Five to nine times apart, on the same failure. Neither
// stopped because it noticed anything: both stopped when the idle timeout
// killed the connection, 3.3s and 2.6s after the cut. What a stack keeps
// sending into a hole is its pre-fault congestion window, which on a fast path
// is megabytes; it is a property of the controller and of the link's history,
// not of the failure. Any detector keyed on "the sender backed off" is
// measuring the wrong object, and on Brutal -- which paces at a declared rate
// and ignores loss by construction -- there is nothing to measure.
//
// 3. A NAIVE THRESHOLD SWITCHES ON A REROUTE, AND THE FLOOR IS THE NEW RTT.
//
// The healthy receive gap is one RTT plus whatever pause the application takes
// between exchanges: 123ms at 50ms RTT, 280ms at 200ms, 462ms at 400ms, 1.019s
// at 1s. A 200ms threshold fires at 203ms on a path that merely rerouted, and
// also on a 30% loss link, and a 100ms one fires on a link with nothing wrong
// with it at all -- including before the fault, on every case in the sweep.
//
// This is not a tuning problem. Until a packet arrives from the far end there
// is no evidence, and a reroute onto a slower path withholds that evidence for
// exactly one new RTT. No detector can be both faster than the new RTT and
// right about a reroute, and the new RTT is precisely the number the client
// does not have. The measured floor is the whole story: 2s buys correctness up
// to a reroute of roughly 1.9s RTT and no further. Above that the Selector
// needs a probe on the candidate, not a cleverer reading of this connection.
//
// Note also that the exculpating signal a design would reach for is not there
// either. "An ack came back, so the path is alive" would be read from
// LatestRTT, and the rate of new RTT samples is 1/RTT: over five runs the 1s
// reroute produced 0 to 8 samples in nine seconds, against 85-87 on a healthy
// 50ms link and 0 to 2 on a blackhole. Rerouted and dead overlap; in one Linux
// run of five the rerouted path produced exactly zero, and 159 packets arrived
// during it. No threshold on RTT freshness separates the two. See
// TestRTTFreshnessIsNotALivenessSignal. The one signal that does separate them
// is the one finding 1 names: packets arrived at all.
//
// 4. DIRECTION IS NOT ATTRIBUTABLE, AND HALF OF IT IS FREE ANYWAY.
//
// down-dead -- the return path is gone -- is indistinguishable from a total
// blackhole at the client: 9.002s against 8.999s of silence, zero fresh RTT
// samples in both, application told at 4.990s against 4.998s. It has to be.
// Our packets arrive, the server acks them, and the acks are what is being
// dropped; an endpoint cannot tell "you never heard me" from "I never heard
// you" using only what it hears. netem's ground truth is the only place the
// difference exists: up 8 of 8 delivered on down-dead, 0 of 8 on blackhole.
//
// up-dead is different, and cheaply so: the client keeps receiving for 2.742s
// after its uplink dies, because the server goes on retransmitting the data it
// had unacked. That is a real discriminator but it is the expensive half, and
// all three modes mean the same thing to a Selector -- switch. It matters only
// because it sets the worst case: the silence has to outlast the peer's own
// retransmissions, which is why the dead-side floor is 5.198s and not 9s, and
// why a 2s detector took up to 5.803s to fire.
//
// 5. THE STACK'S VERDICT IS TOO SLOW, AND ARRIVES BY THE WRONG ROUTE.
//
// With the idle timeout at 4s -- the minimum core/client accepts -- the
// application first learned the connection was gone between 4.990s and 9.659s
// after the cut, against 1.978s to 5.803s for the silence detector. At the
// production default of 30s it would be past 31s. And the error does not
// arrive on a schedule: core/client's TCP() blocks in ReadTCPResponse with no
// deadline of its own, so a caller inside a dial learns nothing until the QUIC
// connection itself expires -- in the sweep, an attempt that started 25ms
// after the cut returned three seconds later. Nor does the API ever say so
// directly: PathStats keeps answering (stats, true) with frozen counters for as
// long as the process lives (TestPathStatsSurvivesTheConnectionItDescribes).
// The Selector cannot wait to be told.
//
// 6. THREE HOLES IN THE API, ONE OF WHICH IS A LATENT BUG.
//
// PacketsLost, BytesLost and LossRate are always zero. quic-go writes them in
// one place only, internal/congestion/cubic_sender.go, and chameleon replaces
// the controller with BBR or Brutal at authentication time. The stay-or-switch
// decision between a blackhole and a merely lossy path therefore cannot be made
// on loss rate at all -- which the numbers happen to permit, since 30% loss
// stays inside the silence threshold, but it is luck rather than design.
// TestPacketsLostIsNeverPopulated holds it.
//
// RFC 9002's PTO count -- the canonical "this path is probably dead" signal,
// which the stack maintains and logs to qlog -- is not on ConnectionStats.
// Neither is the time the last packet was received, which is the quantity the
// idle timeout is itself computed from and exactly the quantity finding 1 says
// to key on. Both are internal to quic-go. A Selector has to reconstruct the
// second by polling and differencing, at whatever resolution it polls, which is
// what harness.Observe does at 20ms and what selectorSilence assumes. Exposing
// either would make the detector exact instead of sampled, and would cost
// nothing.
//
// One thing that was expected to be a hole is not one, and it is recorded
// because the expectation was wrong and someone will have it again. Polling
// PathStats from a goroutine of its own is sound: quic-go's ConnectionStats
// reads six counters from internal/utils.ConnectionStats and four RTT fields
// from internal/utils.RTTStats, and every one of the ten is an atomic. -race on
// the host, over a nine-second observation sampling at 20ms while the
// connection ran, reported nothing. A Selector may sample as often as it likes.
