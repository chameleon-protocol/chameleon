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

// The QUIC parameters this file's bed runs with. They are not what a client
// ships with -- shippedIdleTimeout and shippedKeepAlive are -- and every result
// here is conditional on them, so they are named rather than written into
// pathfailOpts as literals: the silence threshold is derived from them (see
// selectorSilence) and the derivation has to be visible.
//
// The idle timeout is the minimum the core accepts, so that the stack's own
// verdict lands inside a short observation instead of half a minute later. The
// keep-alive is the minimum the core accepts, which is what keeps a connection
// this file leaves idle producing evidence often enough to observe in seconds.
const (
	pathfailIdleTimeout = 4 * time.Second
	pathfailKeepAlive   = 2 * time.Second
)

// What core/client/config.go fills in when the application sets neither, which
// is what a client ships with.
const (
	shippedIdleTimeout = 30 * time.Second
	shippedKeepAlive   = 10 * time.Second
)

func pathfailOpts(seed uint64) harness.Options {
	return harness.Options{
		Profile:         pathfailBase(),
		Seed:            seed,
		MaxIdleTimeout:  pathfailIdleTimeout,
		KeepAlivePeriod: pathfailKeepAlive,
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
	// What selectorSilence derives for this file's bed. The grid has to contain
	// the value actually recommended, or the sweep stops being the thing the
	// recommendation is read from.
	3 * time.Second,
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

// silenceNoiseFloor is what the sweep measured: the shortest silence a link
// that is still carrying traffic can be relied on not to produce.
//
// It is not a round number chosen for looks. Over twelve observations of
// working links under the interactive load, the largest gap between packets
// received was 1.402s (30% loss, one run in five; the other four gave 440ms to
// 619ms). Over eight observations of links that were dead, the slowest a 2s
// detector fired was 5.803s, and it fired on every one. 2s was the shortest
// value on the sweep grid that never fired on a working link and always fired
// on a dead one.
//
// The margin is thin and honestly so: 1.4x, on a tail set by loss rather than
// by anything structural. That is the measurement's real message. It says a 2s
// detection is a reason to go and probe another candidate, not a reason to move
// a live connection on its own -- and the design already has the probe.
//
// It is a floor and not the answer. Every observation behind it kept an
// exchange running every 50ms; a connection whose application has gone quiet
// produces evidence only as often as it pings. See selectorSilence.
const silenceNoiseFloor = 2 * time.Second

// silenceSlack is what a threshold has to add to the keep-alive interval to
// avoid firing on an idle connection that is perfectly healthy.
//
// It covers the round trip the keep-alive's acknowledgement has to make, the
// peer's ack delay, and the resolution at which a detector polls (20ms here).
// Measured, on a 50ms link, in TestSilenceThresholdIsBoundedBelowByTheKeepAlive:
// the longest gap between packets received on an idle connection was 2.061s at
// a 2s keep-alive and 10.061s at 10s -- 61ms of overhead in both, which is the
// round trip plus the sampling and nothing else. The value below is an order of
// magnitude above that, because the round trip it has to cover is the path's
// and not this bed's, and firing on a healthy idle connection is the one
// failure this design cannot afford.
const silenceSlack = time.Second

// selectorSilence is the silence a Selector may read as "this path is dead" on
// a connection configured with these QUIC parameters. It is the only number in
// this file a Selector should copy, and it is a function rather than a constant
// because it is not a property of the network.
//
// Receive silence detects a dead path by the absence of evidence, and evidence
// arrives only in answer to something we sent. What guarantees we send anything
// is the QUIC keep-alive, so on a connection whose application has gone quiet
// -- which is most of a session -- the gap between packets received is the
// keep-alive interval, whatever the network is doing. A threshold below that
// fires on a healthy idle connection, and a Selector that switches paths on an
// idle connection is worse than one that never switches.
//
// quic-go pings at min(KeepAlivePeriod, idleTimeout/2) (connection.go, where
// keepAliveInterval is computed from the negotiated idle timeout), so both
// parameters are needed and neither is the network's to change. Two caveats
// that the parameters do not carry:
//
//   - quic-go raises the interval to 1.5x the PTO on a slow path, so a Selector
//     on a path whose round trip approaches the keep-alive interval must add
//     that term. It can: SmoothedRTT and RTTVariance are on pathstats.Stats.
//   - a peer with a shorter idle timeout than ours only shortens the interval,
//     which is the safe direction.
//
// The result is a detector that beats the stack's own verdict by the ratio
// between the idle timeout and the keep-alive: at the shipped defaults, 11s
// against 30s. It is not a fast detector, and no passive one can be. A Selector
// that wants to know sooner has to produce the evidence itself -- send
// something, and time the answer -- which is the probe the design already has.
func selectorSilence(keepAlive, idleTimeout time.Duration) time.Duration {
	return max(silenceNoiseFloor, min(keepAlive, idleTimeout/2)+silenceSlack)
}

// pathfailSilence is selectorSilence for this file's bed.
func pathfailSilence() time.Duration {
	return selectorSilence(pathfailKeepAlive, pathfailIdleTimeout)
}

// longObs gives nine seconds after the fault. up-dead is the reason: the server
// goes on retransmitting into the void for seconds, so the detector's slowest
// measured firing was 5.803s at a 2s threshold and 5.48s at the 3s one this bed
// derives, and a shorter window would score either as "never".
func longObs(o harness.Observation) harness.Observation {
	o.FaultAt = 2 * time.Second
	o.Duration = 11 * time.Second
	return o
}

// dirWant is what netem's own counters have to show for one direction of the
// link after the fault.
//
// A scenario named for a direction has to assert that direction. Before this
// existed the dead cases asserted require.Zero(upDelivered*downDelivered),
// which is a claim that some direction died: swapping the field assignments in
// netem's WithUpBlackhole and WithDownBlackhole left both up-dead and down-dead
// passing, so the two tests that exist to tell a dead forward path from a dead
// return path could not tell them apart.
type dirWant int

const (
	dirIgnore dirWant = iota // the case makes no claim about this direction
	dirAlive                 // the link carried what it was offered
	dirDead                  // the link dropped what it was offered
)

// checkDir holds one direction's ground truth, from netem's own counters.
//
// offered and dropped are counted from the fault, not from the settle point,
// because the datagrams that were in flight when the fault landed are part of
// the evidence: a blackhole drops those too. delivered is counted from the
// settle point, once the pipe the fault could not reach into has drained.
//
// exercised says whether this direction can be relied on to carry anything at
// all after the fault, and it is the whole reason the two directions are not
// checked the same way. Our own uplink always does: the client goes on sending
// and retransmitting whatever the link does to it. The downlink does only while
// the uplink still delivers -- a server that hears nothing has nothing to
// answer, and under the interactive load it has nothing queued either, so a
// blackholed uplink leaves the downlink offered zero datagrams on some runs
// (measured, on the same case one run to the next: 6 offered and 0). A
// direction that is offered nothing leaves no trace of its state in any
// counter, and asserting one anyway would be asserting the harness's timing.
func checkDir(t *testing.T, dir string, want dirWant, exercised bool, offered, dropped, delivered uint64) {
	t.Helper()
	if want == dirIgnore {
		return
	}
	t.Logf("netem %s: offered %d, dropped %d after the fault, delivered %d after the settle window",
		dir, offered, dropped, delivered)
	if exercised {
		require.Positive(t, offered,
			"%s: nothing crossed this direction after the fault, so its state is not being tested", dir)
	}
	switch want {
	case dirAlive:
		require.Zero(t, dropped, "%s: this direction was supposed to survive the fault", dir)
		if exercised {
			require.Positive(t, delivered, "%s: this direction survived the fault and delivered nothing", dir)
		}
	case dirDead:
		if exercised {
			require.Positive(t, dropped, "%s: this direction was supposed to be blackholed", dir)
		}
		require.Zero(t, delivered, "%s: a blackholed direction delivered", dir)
	}
}

// TestReceiveSilenceSeparatesDeadPathsFromBadOnes is the recommendation held as
// an assertion.
//
// A detector that watches one number -- how long since PacketsReceived last
// increased -- fires on every path that was blackholed in any direction, and
// stays silent on paths that are merely lossy, merely slow, or merely rerouted.
// Nothing else in pathstats.Stats does this; see the findings.
//
// Mutation: with the field assignments in netem's WithUpBlackhole and
// WithDownBlackhole swapped, up-dead fails with '"0" is not positive: up: this
// direction was supposed to be blackholed' and down-dead with "Should be zero,
// but was 21: up: this direction was supposed to survive the fault". Every
// silence assertion below still passes under that swap -- both one-way failures
// look the same from inside the endpoint, which is finding 4 -- so the
// direction has to be asserted from netem's counters or not at all.
func TestReceiveSilenceSeparatesDeadPathsFromBadOnes(t *testing.T) {
	if testing.Short() {
		t.Skip("each case runs a live connection for eleven seconds")
	}
	base := pathfailBase()
	cases := []struct {
		name           string
		fault          netem.Profile
		dead           bool
		wantUp, wantDn dirWant
	}{
		{"none", base.Named("none"), false, dirAlive, dirAlive},
		// 30% loss drops in both directions and delivers in both, which is
		// neither state checkDir knows; the assertions below cover it.
		{"loss30%", base.WithLoss(0.30).Named("loss30%"), false, dirIgnore, dirIgnore},
		{"rtt-step-1s", netem.RTT(time.Second).Named("rtt-step-1s"), false, dirAlive, dirAlive},
		{"blackhole", base.WithBlackhole(true).Named("blackhole"), true, dirDead, dirDead},
		{"up-dead", base.WithUpBlackhole(true).Named("up-dead"), true, dirDead, dirAlive},
		{"down-dead", base.WithDownBlackhole(true).Named("down-dead"), true, dirAlive, dirDead},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := harness.New(t, pathfailOpts(uint64(200+i)))
			rep := env.Observe(longObs(interactive(c.fault)))
			sig := rep.Signature()
			fired := rep.DetectAt(pathfailSilence())
			t.Logf("%s: %s", c.name, sig)
			t.Logf("%s: silence>=%s fires at %s", c.name, pathfailSilence(), fmtNever(fired))

			// Ground truth, from netem's own counters: the link did what the
			// profile said, in the direction the profile named. Without this a
			// case that silently failed to impair anything -- or impaired the
			// wrong direction -- would look like a passing assertion.
			_, upOut, _, downOut := rep.Delivered()
			checkDir(t, "up", c.wantUp, true,
				rep.After.Up.In-rep.Before.Up.In, rep.After.Up.Dropped-rep.Before.Up.Dropped, upOut)
			checkDir(t, "down", c.wantDn, c.wantUp == dirAlive,
				rep.After.Down.In-rep.Before.Down.In, rep.After.Down.Dropped-rep.Before.Down.Dropped, downOut)
			if !c.dead {
				require.Positive(t, downOut, "the link delivered nothing; the case did not run")
			}

			if c.dead {
				require.NotEqual(t, harness.Never, fired, "a dead path was never detected")
				// up-dead is the slow one: the silence has to outlast the
				// peer's own retransmissions, and it fired at 5.48s here
				// against 3.001s for the other two. The worst of the earlier
				// five-run set was 5.803s, at a threshold one second shorter
				// than this one. The bound is above all of those and below the
				// nine seconds of window, so a run that never fired fails here
				// rather than reading as a pass.
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
// the reason silenceNoiseFloor is 2s rather than the 200ms a design would reach
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

	for _, s := range []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, pathfailSilence()} {
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
	assert.Equal(t, harness.Never, rep.DetectAt(pathfailSilence()),
		"the recommended threshold fired on a rerouted but working path")
}

// idleObs is one exchange and then nothing, with the tunnelled connection left
// open: the state a session spends most of its life in, and the state the sweep
// never measured. There is no fault -- the profile it changes to is the profile
// it started with -- because the point is what a healthy link looks like.
func idleObs(profile netem.Profile, d time.Duration) harness.Observation {
	o := interactive(profile)
	o.MaxExchanges = 1
	o.FaultAt = time.Second
	o.Duration = d
	return o
}

// TestSilenceThresholdIsBoundedBelowByTheKeepAlive is why selectorSilence takes
// arguments.
//
// A receive-silence detector fires when the far end stops producing evidence,
// and the far end produces evidence only in answer to something we send. When
// the application is sending, the noise floor is the application's own rhythm,
// which is what the sweep measured with an exchange every 50ms. When it is not,
// the only thing left sending is the QUIC keep-alive, and the gap between
// packets received becomes the keep-alive interval -- on a link with nothing
// whatsoever wrong with it.
//
// The two beds differ only in that interval, 2s against the shipped 10s, and
// the measured gap follows it. That is the dependency: the threshold belongs to
// the connection's configuration, not to the network.
//
// Mutation: with selectorSilence returning silenceNoiseFloor -- the bare
// constant this file used to hold -- both cases fail, shipped-defaults with
// "the derived threshold fired on a healthy idle connection: the far end was
// answering every 10.06s and the threshold is 2s" and test-bed with the same at
// 2.061s. The second is the one worth reading twice: 2s fires on a connection
// whose keep-alive is 2s.
func TestSilenceThresholdIsBoundedBelowByTheKeepAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("holds two connections idle across their keep-alive intervals")
	}
	cases := []struct {
		name            string
		keepAlive, idle time.Duration
		opts            harness.Options
		observe         time.Duration
	}{
		// This file's own bed. Its 2s keep-alive is the minimum the core
		// accepts, and it is the reason the sweep's 2s looked safe.
		{"test-bed", pathfailKeepAlive, pathfailIdleTimeout, pathfailOpts(400), 9 * time.Second},
		// What a client ships with: nothing set, so core/client fills in 30s and
		// 10s. Options carries neither field, so this cannot drift from the
		// defaults the way naming them here would.
		{"shipped-defaults", shippedKeepAlive, shippedIdleTimeout,
			harness.Options{Profile: pathfailBase(), Seed: 401}, 25 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := harness.New(t, c.opts)
			rep := env.Observe(idleObs(pathfailBase().Named("none"), c.observe))
			sig := rep.Signature()
			want := selectorSilence(c.keepAlive, c.idle)
			t.Logf("%s: %s", c.name, sig)
			t.Logf("%s: keep-alive %s, longest gap between packets received %s, threshold %s fires at %s, %s fires at %s",
				c.name, c.keepAlive, sig.RxGapMax.Round(time.Millisecond),
				silenceNoiseFloor, fmtNever(rep.DetectAt(silenceNoiseFloor)),
				want, fmtNever(rep.DetectAt(want)))

			// The connection is healthy and stays healthy: the keep-alive is
			// answered, so packets keep arriving, and nothing ever reports the
			// connection gone. Without this the silence below could be the
			// silence of a connection that had simply died.
			require.Positive(t, sig.RxAfter, "no packets arrived while the connection was idle")
			require.Equal(t, harness.Never, sig.GoneAt, "the idle connection did not survive")
			_, _, _, downOut := rep.Delivered()
			require.Positive(t, downOut, "the link delivered nothing; the case did not run")

			// The gap is the keep-alive interval, not the network. Both bounds
			// matter: below it, the measurement did not last long enough to
			// contain a whole interval and proves nothing; above it, something
			// other than the keep-alive is producing the evidence.
			assert.Greater(t, sig.RxGapMax, c.keepAlive,
				"the idle gap was shorter than the keep-alive interval; something else was sending")
			assert.Less(t, sig.RxGapMax, c.keepAlive+silenceSlack,
				"the idle gap overran the keep-alive interval by more than the slack allows for")

			assert.Equal(t, harness.Never, rep.DetectAt(want),
				"the derived threshold fired on a healthy idle connection: the far end was answering every %s and the threshold is %s",
				sig.RxGapMax.Round(time.Millisecond), want)

			// And the bare constant this file used to recommend fires on both
			// beds, which is the finding. It fires even on the bed whose
			// keep-alive is the constant itself: the answer to a ping cannot
			// come back faster than the round trip.
			assert.NotEqual(t, harness.Never, rep.DetectAt(silenceNoiseFloor),
				"a bare %s threshold did not fire on an idle connection; the keep-alive is not the floor after all",
				silenceNoiseFloor)
		})
	}
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
	fired := rep.DetectAt(pathfailSilence())
	t.Logf("blackhole: %s", sig)
	t.Logf("blackhole: silence>=%s fires at %s, the application learned the connection was gone at %s",
		pathfailSilence(), fmtNever(fired), fmtNever(sig.GoneAt))

	_, upOut, _, downOut := rep.Delivered()
	require.Zero(t, upOut+downOut, "the blackhole delivered something")
	require.NotEqual(t, harness.Never, sig.GoneAt, "the stack never gave up inside the window")
	require.NotEqual(t, harness.Never, fired)

	// Measured: fired at 2.98s, application told at 5.028s. The bounds are three
	// separate claims rather than a ratio.
	//
	// The detector fires promptly once the threshold has elapsed -- and slightly
	// before it, measured from the fault, because the silence starts at the last
	// packet received and that was 20ms before the cut. The bound is a second
	// above the threshold, which is what the threshold's own definition allows:
	// the pre-fault sample this is measured from can be up to the sampling
	// interval old, and the run loop wakes on its own timers.
	assert.Less(t, fired, pathfailSilence()+time.Second,
		"the detector was slower than every run measured")
	// The stack cannot be quicker than the idle timeout it is waiting out.
	assert.Greater(t, sig.GoneAt, pathfailIdleTimeout,
		"the stack reported the loss faster than its own idle timeout, which it cannot")
	// And the point of the test: the detector got there first. At this bed's 4s
	// idle timeout that margin is 2s; at the shipped 30s it is the difference
	// between 11s and 31s.
	assert.Less(t, fired, sig.GoneAt, "the stack noticed before the detector did")
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

// renoOpts leaves quic-go's own congestion controller in place.
//
// CongestionConfig.Type "reno" is the one setting under which core/client
// installs nothing of its own (internal/congestion.UseConfigured returns
// early), so it is the only way to see what the stack reports when we have not
// replaced the controller. It must not declare a bandwidth: a declared rate
// installs Brutal whatever the congestion type says.
func renoOpts(seed uint64) harness.Options {
	o := pathfailOpts(seed)
	o.Congestion = "reno"
	return o
}

// TestPacketsLostNeedsTheControllerWeReplace is the API gap that matters most,
// because keying the stay-or-switch decision on a loss rate is the obvious
// design and it cannot be built here.
//
// The gap is ours, not quic-go's, and the distinction is the whole point of the
// test. quic-go increments ConnectionStats.PacketsLost and BytesLost in exactly
// one place -- internal/congestion/cubic_sender.go, in OnPacketLost -- so the
// counters describe whatever controller the connection is running only if that
// controller is quic-go's own. core/client replaces it, with Brutal when a rate
// was declared and with BBR otherwise, as soon as authentication finishes; both
// replacements leave the counter untouched forever. "Loss is never reported" is
// therefore the wrong claim, and the difference is one config field.
//
// Both halves run the same 30% loss in both directions under the same bulk
// load. The only difference between them is which controller the connection
// ends up on, and that is what the counter follows.
//
// Mutation: with installCongestionControl returning without installing
// anything, the brutal case fails with "Should be zero, but was 146:
// PacketsLost moved; the negotiated controller may not have been installed, and
// the loss signal is usable after all" and the bbr case with the same at 4380.
// With UseConfigured installing BBR for every type instead, the reno case fails
// with '"0" is not positive: PacketsLost did not move; quic-go's own sender is
// what writes it'.
func TestPacketsLostNeedsTheControllerWeReplace(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two live connections for eleven seconds each")
	}
	cases := []struct {
		name string
		opts func(uint64) harness.Options
		// ours says core/client replaced the controller with one of its own.
		ours bool
	}{
		// Brutal, which is what every connection that declares a rate gets.
		{"brutal", brutalOpts, true},
		// BBR, which is what every other shipped configuration gets.
		{"bbr", pathfailOpts, true},
		// quic-go's own sender, reachable only by configuring reno.
		{"reno", renoOpts, false},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := harness.New(t, c.opts(uint64(303+10*i)))
			rep := env.Observe(longObs(bulk(pathfailBase().WithLoss(0.30).Named("loss30%"))))
			sig := rep.Signature()

			// Ground truth: the link really did lose a large fraction of what it
			// was given, in both directions.
			upIn, upOut, downIn, downOut := rep.Delivered()
			require.Positive(t, upIn)
			require.Positive(t, downIn)
			upLoss := 1 - float64(upOut)/float64(upIn)
			downLoss := 1 - float64(downOut)/float64(downIn)
			t.Logf("netem delivered %d of %d offered up (%.1f%% dropped) and %d of %d down (%.1f%% dropped)",
				upOut, upIn, upLoss*100, downOut, downIn, downLoss*100)
			require.Greater(t, upLoss, 0.2, "the link was not actually lossy")
			require.Greater(t, downLoss, 0.2, "the link was not actually lossy")

			// The neighbouring counters move, so the struct is live and being
			// read and the reading below is a fact about the field rather than
			// about the test.
			require.Positive(t, sig.TxAfter, "PacketsSent did not move")
			require.Positive(t, sig.RxAfter, "PacketsReceived did not move")

			last := rep.Samples[len(rep.Samples)-1].Stats
			t.Logf("pathstats under that loss: sent=%d received=%d lost=%d bytes-lost=%d loss-rate=%v lost-delta=%+d",
				last.PacketsSent, last.PacketsReceived, last.PacketsLost, last.BytesLost,
				last.LossRate(), sig.LostDelta)
			if c.ours {
				assert.Zero(t, last.PacketsLost,
					"PacketsLost moved; the negotiated controller may not have been installed, and the loss signal is usable after all")
				assert.Zero(t, last.BytesLost, "BytesLost moved")
				assert.Zero(t, last.LossRate(), "LossRate moved")
				assert.Zero(t, sig.LostDelta)
				assert.Zero(t, sig.LostStepMin)
				return
			}
			assert.Positive(t, last.PacketsLost,
				"PacketsLost did not move; quic-go's own sender is what writes it")
			assert.Positive(t, last.BytesLost, "BytesLost did not move")
			assert.Positive(t, last.LossRate(), "LossRate did not move")
			assert.Positive(t, sig.LostDelta, "PacketsLost did not move after the fault")
		})
	}
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
//   - PacketsLost, BytesLost and LossRate stay at zero for as long as we keep
//     replacing the congestion controller, which is always (finding 6).
//   - PacketsSent says what the congestion controller did (finding 2).
//
// A detector is one subtraction on one counter: how long since PacketsReceived
// last increased. What it has to be compared against is not a constant, and
// that is finding 7; silenceNoiseFloor holds what this table supports, and
// selectorSilence turns it into a threshold.
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
// The same argument bounds the threshold from the other side in finding 7,
// where the evidence is withheld not by the path but by our own keep-alive.
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
// How much the server keeps sending is not something the bed can promise. Under
// the interactive load it has nothing queued, so on some runs of up-dead it
// offers the downlink datagrams after the cut and on others exactly zero
// (measured: 6 and 0 on the same case). That is why checkDir asserts the
// downlink's state only when the uplink is still delivering, and why the
// direction each scenario is named for is asserted from netem's counters --
// nothing inside the endpoint can tell the two apart, which is this finding.
//
// 5. THE STACK'S VERDICT IS TOO SLOW, AND ARRIVES BY THE WRONG ROUTE.
//
// With the idle timeout at 4s -- the minimum core/client accepts -- the
// application first learned the connection was gone between 4.990s and 9.659s
// after the cut, against 1.978s to 5.803s for a 2s silence detector and 2.98s
// to 5.48s for the 3s one this bed now derives. At the production default of
// 30s the stack's verdict would be past 31s, against 11s for the detector. And the error does not
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
// PacketsLost, BytesLost and LossRate stay at zero, and the reason is ours
// rather than quic-go's. quic-go writes them in one place only,
// internal/congestion/cubic_sender.go, so they describe the connection's
// congestion controller only while that controller is quic-go's own; chameleon
// replaces it with Brutal or BBR at authentication time and the counters never
// move again. Measured under 30% loss in both directions: 0 packets lost on
// Brutal and on BBR, 3939 on the same bed with CongestionConfig.Type "reno",
// which is the one setting that leaves the stack's sender in place. "Loss is
// never reported" would be the wrong claim -- the signal exists and we switch
// it off. The stay-or-switch decision between a blackhole and a merely lossy
// path therefore cannot be made on loss rate in any shipped configuration,
// which the numbers happen to permit, since 30% loss stays inside the silence
// threshold, but it is luck rather than design.
// TestPacketsLostNeedsTheControllerWeReplace holds both halves.
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
//
// 7. THE THRESHOLD IS NOT A NUMBER. IT IS THE KEEP-ALIVE.
//
// Everything above was measured with an exchange every 50ms, so the far end had
// a reason to answer twenty times a second and the noise floor was the
// application's own rhythm. That is not the state a session spends its time in.
// With the application quiet and the tunnel still open, the only thing left
// producing evidence is the QUIC keep-alive, and the gap between packets
// received becomes the keep-alive interval on a link with nothing wrong with
// it. Measured on a clean 50ms link, one exchange and then silence:
//
//	keep-alive 2s (this file's bed)     longest receive gap 2.061s
//	keep-alive 10s (shipped default)    longest receive gap 10.061s
//
// 61ms of overhead in both -- the round trip plus the 20ms sampling -- and the
// interval is what moved. A bare 2s threshold fires on both of them: at 2s on
// the shipped bed, and at 3.18s even on the bed whose keep-alive is 2s, because
// the answer to a ping cannot come back faster than the round trip. The earlier
// claim that 2s "never fired on a working link" was true only of links that
// something was using at the time, which the sweep never said.
//
// So the threshold is a function of the connection's own configuration:
// max(2s, min(KeepAlivePeriod, idleTimeout/2) + 1s), which is selectorSilence.
// At the shipped 30s/10s that is 11s, against a stack verdict past 31s. The
// slack covers the round trip, the peer's ack delay and the polling interval;
// on a path slow enough that quic-go raises the ping interval to 1.5x the PTO,
// a Selector has to add that term, and it can, from SmoothedRTT and
// RTTVariance.
//
// The consequence is worth stating plainly, because it is the ceiling on this
// whole approach: a passive detector cannot be faster than the rate at which
// the connection gives the far end something to answer. A Selector that wants
// to know sooner has to make the evidence itself -- send, and time the answer.
// That is the probe, and finding 3 already needed it for reroutes past ~1.9s.
// TestSilenceThresholdIsBoundedBelowByTheKeepAlive holds this one.
