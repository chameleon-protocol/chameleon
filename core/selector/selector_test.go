package selector

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/core/v2/pathstats"
)

// The policy is a pure function of observations, so it is held to tables of
// them. Every duration a test expects is written out as a literal computed by
// hand from the terms in selector.go -- never by calling Threshold, which would
// be the constants checking themselves.
//
// The gaps the tables replay are the measured ones. They come from a sweep over
// blackholes, heavy loss, RTT steps and one-way failures on a real connection
// across an impaired link, at the parameters testBed names, and they are cited
// case by case where they are used.

// testBed is the QUIC configuration every measured gap in this file was recorded
// at: the minimum idle timeout core/client accepts and the minimum keep-alive,
// which is what let a twelve-second observation contain several keep-alive
// intervals.
//
// Its threshold is min(2s, 4s/2) + 50ms + 2s = 4.05s at the bed's round trip.
const (
	bedKeepAlive = 2 * time.Second
	bedIdle      = 4 * time.Second
	bedSRTT      = 50 * time.Millisecond
	bedVar       = 10 * time.Millisecond
	bedThreshold = 4050 * time.Millisecond
)

// shipped is what a client that configures neither gets from core/client, and
// its threshold is min(10s, 30s/2) + 50ms + 2s = 12.05s.
const (
	shippedKeepAlive = 10 * time.Second
	shippedIdle      = 30 * time.Second
	shippedThreshold = 12050 * time.Millisecond
)

// measuredNoiseFloor is the sweep's own answer, written out here rather than
// read from the package: 2s was the shortest value on the sweep grid that never
// fired on a working link and always fired on a dead one. The policy no longer
// carries it as a term -- the slack alone is that big -- so what remains to
// check is that no configuration computes a threshold below it.
const measuredNoiseFloor = 2 * time.Second

// poll is the interval the measurements were sampled at, and therefore the
// interval these tables step at: a decision no faster than the readings it is
// made from.
const poll = 20 * time.Millisecond

var (
	candA = netip.MustParseAddrPort("127.0.0.1:1001")
	candB = netip.MustParseAddrPort("127.0.0.1:1002")
	candC = netip.MustParseAddrPort("127.0.0.1:1003")
)

func bedConfig(candidates ...netip.AddrPort) Config {
	return Config{KeepAlive: bedKeepAlive, IdleTimeout: bedIdle, Candidates: candidates}
}

// event is one decision and when it was taken, measured from the start of the
// run so that a test can assert how long a detection took.
type event struct {
	at time.Duration
	d  Decision
}

// driver feeds a Selector synthetic readings at poll intervals. It holds the
// counter and the clock across calls so that a run can change what the link is
// doing halfway through, which is what every failure case is.
//
// It obeys the decisions it is given, because that is the contract Observe
// documents and a table that ignored a switch would be measuring a caller bug
// rather than the policy. The tests that need a move nobody ordered turn obey
// off and set the address themselves.
type driver struct {
	t    *testing.T
	s    *Selector
	base time.Time

	now    time.Duration
	rx     uint64
	lastRx time.Duration
	on     netip.AddrPort
	srtt   time.Duration
	rttvar time.Duration
	live   bool
	obey   bool
}

func newDriver(t *testing.T, cfg Config, on netip.AddrPort) *driver {
	t.Helper()
	return &driver{
		t: t, s: New(cfg), base: time.Unix(0, 0),
		on: on, srtt: bedSRTT, rttvar: bedVar, live: true, obey: true,
	}
}

// run polls for dur. A gap of zero means nothing arrives, which is what every
// blackhole and every one-way failure looked like from inside the endpoint.
func (dr *driver) run(dur, gap time.Duration) []event {
	dr.t.Helper()
	var out []event
	end := dr.now + dur
	for dr.now < end {
		dr.now += poll
		if gap > 0 && dr.now-dr.lastRx >= gap {
			dr.rx++
			dr.lastRx = dr.now
		}
		o := Observation{At: dr.base.Add(dr.now), On: dr.on, Live: dr.live}
		if dr.live {
			o.Stats = pathstats.Stats{
				PacketsReceived: dr.rx,
				SmoothedRTT:     dr.srtt,
				RTTVariance:     dr.rttvar,
			}
		}
		d := dr.s.Observe(o)
		if d.Action == Switch && dr.obey {
			dr.on = d.To
		}
		out = append(out, event{at: dr.now, d: d})
	}
	return out
}

func switchesIn(evs []event) []netip.AddrPort {
	var out []netip.AddrPort
	for _, e := range evs {
		if e.d.Action == Switch {
			out = append(out, e.d.To)
		}
	}
	return out
}

// firstNot returns the first decision that was not the given action.
func firstNot(evs []event, a Action) (event, bool) {
	for _, e := range evs {
		if e.d.Action != a {
			return e, true
		}
	}
	return event{}, false
}

func actionsOf(evs []event) []Action {
	var out []Action
	for _, e := range evs {
		if len(out) == 0 || out[len(out)-1] != e.d.Action {
			out = append(out, e.d.Action)
		}
	}
	return out
}

// TestThresholdIsTheConnectionsOwnConfiguration is the threshold itself, term by
// term. Each row is arithmetic done by hand from the constants in selector.go,
// so moving any one of them fails a row.
//
// Mutation, one constant at a time, confirmed by grep and by running this test:
//
//   - silenceSlack 2s -> 0: every row fails, starting with "expected: 12.05s
//     actual: 10.05s".
//   - silenceSlack 2s -> 1s, which is what it was when the reroute sweep
//     condemned a working path: every row fails, starting with "expected: 12.05s
//     actual: 11.05s".
//   - the IdleTimeout/2 clamp removed: "idle timeout halves the period" fails
//     with "expected: 4.05s actual: 12.05s".
//   - the 1.5*PTO term removed: "slow path, keep-alive too short for it" fails
//     with "expected: 8.5375s actual: 6s" and "variance floor visible" with
//     "expected: 27.039s actual: 22s".
//   - ackDelay 25ms -> 0: "slow path" fails with "expected: 8.5375s actual:
//     8.5s" and "variance floor visible" with "actual: 27.0015s".
//   - granularity 1ms -> 0: "variance floor visible" fails with "expected:
//     27.039s actual: 27.0375s".
//   - the SmoothedRTT term removed: four rows fail, "shipped defaults" with
//     "expected: 12.05s actual: 12s" and "slow path" with "expected: 8.5375s
//     actual: 6.5375s".
func TestThresholdIsTheConnectionsOwnConfiguration(t *testing.T) {
	cases := []struct {
		name            string
		keepAlive, idle time.Duration
		srtt, rttvar    time.Duration
		want            time.Duration
	}{
		// min(10s, 15s) + 50ms + 2s.
		{"shipped defaults", shippedKeepAlive, shippedIdle, bedSRTT, bedVar, shippedThreshold},
		// min(2s, 2s) + 50ms + 2s. This is the bed every measured gap came from.
		{"test bed", bedKeepAlive, bedIdle, bedSRTT, bedVar, bedThreshold},
		// min(10s, 2s) + 50ms + 2s: quic-go pings at half the negotiated idle
		// timeout when the configured period is longer, so a threshold that used
		// the configured period would sit 8s above the interval that matters.
		{"idle timeout halves the period", shippedKeepAlive, bedIdle, bedSRTT, bedVar, bedThreshold},
		// 1.5*(2s + 4*250ms + 25ms) = 4.5375s, which beats the 2s period, then
		// + 2s + 2s. A path this slow is pinged at the PTO's rhythm, not the
		// configured one, and a threshold that ignored that would fire on it.
		{"slow path, keep-alive too short for it", bedKeepAlive, bedIdle,
			2 * time.Second, 250 * time.Millisecond, 8537500 * time.Microsecond},
		// 4*0 is below the timer granularity, so the PTO is 10s + 1ms + 25ms;
		// 1.5 of that is 15.039s, then + 10s + 2s.
		{"variance floor visible", shippedKeepAlive, shippedIdle,
			10 * time.Second, 0, 27039 * time.Millisecond},
		// A Config core/client would reject, and the smallest threshold anything
		// can ask for: 1.5*(0 + 1ms + 25ms) = 39ms of interval, no round trip,
		// and the slack.
		{"hand-built config below everything the core accepts", time.Millisecond, bedIdle, 0, 0, 2039 * time.Millisecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Threshold(
				Config{KeepAlive: c.keepAlive, IdleTimeout: c.idle},
				pathstats.Stats{SmoothedRTT: c.srtt, RTTVariance: c.rttvar})
			assert.Equal(t, c.want, got)
		})
	}
}

// TestNoConfigurationComputesAThresholdUnderTheMeasuredFloor is what became of
// the floor the sweep chose once the slack grew to equal it.
//
// The policy used to carry that 2s as a max() term, and the honest reading of
// the sweep was always that it never bound on anything core/client would build:
// the keep-alive is clamped to [2s, 60s] and the idle timeout to [4s, 120s]
// (core/client/config.go), so the interval-based term was never the smaller one.
// Now it cannot bind on any Config at all, because the slack alone is the floor
// and the other two terms cannot be negative. A term that cannot be reached is
// not a guard, so it is gone and the property it stood for is asserted here
// instead, including on configurations assembled by hand that the core would
// reject.
//
// Mutation: with silenceSlack at 1s -- its value when the reroute sweep
// condemned a working path -- this fails with "keep-alive 1ms, idle 4s
// computes 1.039s, under the 2s the sweep measured".
func TestNoConfigurationComputesAThresholdUnderTheMeasuredFloor(t *testing.T) {
	// The bounds core/client/config.go enforces and the values it fills in, plus
	// three values no configuration would ever hold, because the claim is about
	// all of them now.
	keepAlives := []time.Duration{time.Millisecond, 100 * time.Millisecond, 2 * time.Second, 10 * time.Second, 60 * time.Second}
	idles := []time.Duration{time.Millisecond, 4 * time.Second, 30 * time.Second, 120 * time.Second}
	for _, ka := range keepAlives {
		for _, idle := range idles {
			cfg := Config{KeepAlive: ka, IdleTimeout: idle}
			// The most favourable case for a short threshold: a connection
			// reporting no round trip at all, so nothing but the interval and the
			// slack is there to make it up.
			got := Threshold(cfg, pathstats.Stats{})
			assert.GreaterOrEqual(t, got, measuredNoiseFloor,
				"keep-alive %v, idle %v computes %v, under the %v the sweep measured",
				ka, idle, got, measuredNoiseFloor)
		}
	}
}

// TestAPathThatIsMerelySlowOrLossyIsNotDead is the first thing the policy must
// not do, held against every working link the sweep measured.
//
// Each gap below is that case's longest run with no packet received, recorded on
// a real connection at testBed's parameters under a small exchange every 50ms.
// The two that decide it were repeated five times and the worst of the five is
// what is replayed. The connection they describe is working -- the application
// never saw a failure in any of them -- so every decision here has to be to
// stay.
//
// Mutation: with the policy switching at a quarter of its threshold -- quiet
// >= threshold/4, i.e. 1.0125s -- loss30% and rtt-step-1s both fail with "a
// working path was declared dead at 1.04s: switch (silent, quiet 1.02s of
// 4.05s) -> 127.0.0.1:1002". A third of the threshold breaks only loss30%,
// with "declared dead at 1.38s: switch (silent, quiet 1.36s of 4.05s)", and
// that is the margin stated plainly: the worst silence a working link produced
// was 1.402s against a threshold of 4.05s.
func TestAPathThatIsMerelySlowOrLossyIsNotDead(t *testing.T) {
	cases := []struct {
		name string
		gap  time.Duration
	}{
		{"none", 123 * time.Millisecond},
		{"loss30%-brutal", 39 * time.Millisecond},
		{"rtt-step-200ms", 280 * time.Millisecond},
		{"rtt-step-400ms", 462 * time.Millisecond},
		// The two worst working links measured, over five repeats each. These are
		// the whole margin: 1.402s against a 4.05s threshold, and the shortest
		// silence any dead link produced was 5.198s.
		{"loss30%, worst of five", 1402 * time.Millisecond},
		{"rtt-step-1s, worst of five", 1062 * time.Millisecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dr := newDriver(t, bedConfig(candA, candB, candC), candA)
			evs := dr.run(12*time.Second, c.gap)
			if bad, ok := firstNot(evs, Stay); ok {
				t.Fatalf("a working path was declared dead at %v: %v", bad.at, bad.d)
			}
			assert.Equal(t, Alive, evs[len(evs)-1].d.Reason)
		})
	}
}

// TestAnIdleConnectionIsNotADeadOne is the second thing the policy must not do,
// and the reason the threshold is not a constant.
//
// A connection whose application has gone quiet produces evidence only as often
// as QUIC pings, so on a link with nothing whatsoever wrong with it the gap
// between packets received is the keep-alive interval plus the round trip. Both
// gaps below were measured that way, one exchange and then silence: 2.061s at a
// 2s keep-alive and 10.061s at the shipped 10s.
//
// Mutation: with silenceSlack at zero both cases fail, the shipped one with
// "an idle healthy connection was declared dead at 20.14s: switch (silent,
// quiet 10.06s of 10.05s)" and the bed with the same at 2.06s of 2.05s. The
// second is the one worth reading twice: a 2s threshold fires on a connection
// whose keep-alive is 2s, because the answer to a ping cannot come back faster
// than the round trip.
func TestAnIdleConnectionIsNotADeadOne(t *testing.T) {
	cases := []struct {
		name            string
		keepAlive, idle time.Duration
		gap             time.Duration
		observe         time.Duration
	}{
		{"test bed", bedKeepAlive, bedIdle, 2061 * time.Millisecond, 20 * time.Second},
		{"shipped defaults", shippedKeepAlive, shippedIdle, 10061 * time.Millisecond, 60 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dr := newDriver(t, Config{
				KeepAlive: c.keepAlive, IdleTimeout: c.idle,
				Candidates: []netip.AddrPort{candB, candC},
			}, candA)
			evs := dr.run(c.observe, c.gap)
			if bad, ok := firstNot(evs, Stay); ok {
				t.Fatalf("an idle healthy connection was declared dead at %v: %v", bad.at, bad.d)
			}
		})
	}
}

// TestAnIdleConnectionThatReroutedIsNotADeadOne is the case the round-trip term
// cannot cover, swept until it broke.
//
// A reroute is the case where switching is definitely wrong: the path works, it
// is just further away, and the candidate the policy would move to has to be
// re-measured from nothing while this one is answering every ping. What makes it
// hard is that SmoothedRTT only moves when an answer arrives and the answer is
// what is late, so the threshold is computed from the round trip the path had
// before while the gap is made of the round trip it has now. The whole reroute
// has to fit in silenceSlack, which is why the slack is what it is.
//
// The bed is the 2s keep-alive with the shipped 30s idle timeout -- the e2e
// bed, so the sweep and the live test are the same connection -- SmoothedRTT
// held at the 50ms the path had before the reroute, and the gap between packets
// received is the interval plus the rerouted round trip, which is what an idle
// connection produces. The sweep steps the rerouted round trip by 50ms and
// asserts both sides of the bound, because a tolerance asserted only where it
// holds is not a tolerance anybody can rely on.
//
// The bound is 2.05s of rerouted round trip. Above it a working path is still
// condemned, and that is recorded here rather than hidden: no passive reading of
// this connection can do better, because the evidence that would exculpate the
// path is the answer that has not arrived yet.
//
// Mutation: with silenceSlack back at the 1s it was when this sweep was first
// run, every row from 1.1s to 2.05s fails, the first with "a path answering
// every ping at a 1.1s round trip was abandoned at 3.08s: switch (silent,
// quiet 3.06s of 3.05s) -> 127.0.0.1:1002". The rows above the bound go on
// passing, because they switch either way: what the mutation moves is the
// bound itself, from 2.05s of rerouted round trip to 1.05s.
func TestAnIdleConnectionThatReroutedIsNotADeadOne(t *testing.T) {
	// The largest rerouted round trip the policy tolerates: the threshold is
	// 2s + 50ms + 2s and the gap it has to survive is 2s + this.
	const tolerated = 2050 * time.Millisecond

	for rtt := 900 * time.Millisecond; rtt <= 2500*time.Millisecond; rtt += 50 * time.Millisecond {
		t.Run(rtt.String(), func(t *testing.T) {
			dr := newDriver(t, Config{
				KeepAlive: bedKeepAlive, IdleTimeout: shippedIdle,
				Candidates: []netip.AddrPort{candB, candC},
			}, candA)
			// Long enough for several keep-alive intervals to pass, which is what
			// the shipped code needed to cycle its candidates.
			evs := dr.run(30*time.Second, bedKeepAlive+rtt)

			if rtt <= tolerated {
				if bad, ok := firstNot(evs, Stay); ok {
					t.Fatalf("a path answering every ping at a %v round trip was abandoned at %v: %v",
						rtt, bad.at, bad.d)
				}
				return
			}
			// And past the bound it does condemn it. This half is not a wish, it
			// is the limit being stated: a reroute this large is indistinguishable
			// from a path that has stopped answering.
			_, ok := firstNot(evs, Stay)
			assert.Truef(t, ok, "the stated bound of %v is wrong: %v was tolerated too", tolerated, rtt)
		})
	}
}

// TestAnIdleConnectionOnAFarPathIsNotADeadOne is the same claim on a path far
// enough that the two derived terms of the threshold are what carry it.
//
// Read the provenance before the numbers. The gap replayed here is NOT measured;
// it is computed from quic-go's own scheduling, and the test is therefore a
// check that the policy applies that scheduling, not evidence that quic-go
// behaves this way. quic-go pings when nothing has been received for
// max(min(KeepAlivePeriod, idleTimeout/2), 1.5*PTO) -- connection.go's
// nextKeepAliveTime -- so on a 3s path with a 250ms variance the PTO is
// 3s + 1s + 25ms and the interval is 1.5 of that, 6.0375s, not the configured
// 2s. The answer to that ping then takes another 3s to arrive, so the gap
// between packets received on a connection with nothing wrong with it is about
// 9.04s.
//
// This is a path that is already far away rather than one that has just become
// far away, which is the difference between this test and the reroute sweep
// above: here SmoothedRTT has caught up, and both derived terms carry it.
//
// Mutation: with the 1.5*PTO term removed the threshold falls to 2s + 3s + 2s
// and this fails with "a healthy connection on a far path was declared dead at
// 7.02s: switch (silent, quiet 7s of 7s) -> 127.0.0.1:1002"; with the
// SmoothedRTT term removed it falls to 6.0375s + 2s and fails with "declared
// dead at 8.06s: switch (silent, quiet 8.04s of 8.038s)".
func TestAnIdleConnectionOnAFarPathIsNotADeadOne(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.srtt, dr.rttvar = 3*time.Second, 250*time.Millisecond

	// 6.0375s of ping interval plus 3s for the answer, rounded up to a reading.
	evs := dr.run(60*time.Second, 9040*time.Millisecond)
	if bad, ok := firstNot(evs, Stay); ok {
		t.Fatalf("a healthy connection on a far path was declared dead at %v: %v", bad.at, bad.d)
	}
}

// TestABlackholedPathIsSwitchedAwayFrom is the decision the whole component
// exists to make.
//
// The sweep's dead cases produced 5.198s to 9.002s with no packet received, and
// the application was not told the connection was finished until between 4.990s
// and 9.659s -- so a detector that fires at 4.05s still gets there first in
// every one of them, by 0.94s in the quickest. That margin is what the slack
// spends and why it is not larger. The run here gives the link three seconds of health and
// then nothing, which is the blackhole.
//
// Mutation: with the switch suppressed -- Observe returning Stay where it
// returns Switch -- this fails at the require with "a blackholed path was
// never left".
func TestABlackholedPathIsSwitchedAwayFrom(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	healthy := dr.run(3*time.Second, 123*time.Millisecond)
	require.False(t, hasNonStay(healthy), "the healthy window already decided something")

	evs := dr.run(5*time.Second, 0)
	got, ok := firstNot(evs, Stay)
	require.True(t, ok, "a blackholed path was never left")
	assert.Equalf(t, Switch, got.d.Action, "%v", got.d)
	assert.Equalf(t, Silent, got.d.Reason, "%v", got.d)
	assert.Equal(t, candB, got.d.To, "the first untried candidate is the one to take")

	// The detection lands one poll after the threshold at the latest: the
	// silence is measured from the last reading in which the counter moved, and
	// that reading can be a whole poll interval old.
	quiet := got.d.Silence
	assert.GreaterOrEqual(t, quiet, bedThreshold, "the policy fired before its own threshold")
	assert.Less(t, quiet, bedThreshold+poll, "the policy was slower than one reading")

	// And it fires once, not on every subsequent reading: the clock restarts at
	// the switch, so the candidate it moved to gets a full threshold of its own.
	assert.Equal(t, []Action{Stay, Switch, Stay}, actionsOf(evs))
}

func hasNonStay(evs []event) bool {
	_, ok := firstNot(evs, Stay)
	return ok
}

// TestOneSwitchPerThreshold is the hysteresis, stated as the only thing it is: a
// switch restarts the silence clock, so nothing can order another one until a
// whole threshold has passed on the candidate just moved to.
//
// It matters because a switch is not free. It costs a round trip before the
// connection is usable -- the path state is thrown away and re-measured -- and a
// congestion controller reset on top of it. A policy that re-decided every 20ms
// while a dead candidate stayed dead would spend the outage moving.
//
// Mutation: with the restart(o.At) call removed from the switch path in
// Observe, this fails with "expected one switch per 4.05s threshold, got 2 in
// the first six seconds of silence" -- the whole candidate list spent in two
// consecutive readings, forty milliseconds apart -- and then with "the second
// candidate never got its verdict", because there was no candidate left by the
// time the second window started.
func TestOneSwitchPerThreshold(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.run(time.Second, 123*time.Millisecond)

	// Six seconds of unbroken silence is one threshold and most of another, so
	// a policy that restarts its clock at the switch decides exactly once.
	evs := dr.run(6*time.Second, 0)
	assert.Equalf(t, 1, countSwitches(evs),
		"expected one switch per %v threshold, got %d in the first six seconds of silence",
		bedThreshold, countSwitches(evs))

	// The candidate it moved to gets the same threshold and no less.
	assert.Equal(t, 1, countSwitches(dr.run(5*time.Second, 0)),
		"the second candidate never got its verdict")
}

func countSwitches(evs []event) int {
	n := 0
	for _, e := range evs {
		if e.d.Action == Switch {
			n++
		}
	}
	return n
}

// TestEveryCandidateIsTriedOnceAndThenTheDecisionIsGivenUp answers the question
// the task asks plainly: what happens when nothing works.
//
// Each candidate gets one threshold to prove itself, in the caller's order, and
// when the list is exhausted the policy gives up and keeps giving up. It does
// not cycle. Cycling would be a policy that spends a dead network's entire
// duration paying a round trip and a controller reset every threshold, and
// there is no measurement anywhere that says a candidate which was silent four
// seconds ago is worth another try now. What to do instead -- redial, go and
// find more candidates, tell the user -- is outside this package, which is why
// GiveUp is a decision and not a silence.
//
// Mutation: with the tried map never written, the action sequence gains a
// third switch instead of ending in give-up and the addresses switched to read
// 1002, 1001, 1002 -- the policy walking back and forth between the candidate
// it started on and the first one it left, which is precisely the flap that
// costs a round trip and a controller reset each way -- and the last loop
// fails with "the policy went round again".
func TestEveryCandidateIsTriedOnceAndThenTheDecisionIsGivenUp(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.run(time.Second, 123*time.Millisecond)

	evs := dr.run(15*time.Second, 0)
	assert.Equal(t, []Action{Stay, Switch, Stay, Switch, Stay, GiveUp}, actionsOf(evs))
	assert.Equal(t, []netip.AddrPort{candB, candC}, switchesIn(evs),
		"the candidate the connection started on is tried by being on it, not by being switched to")

	// And it stays given up rather than starting the walk again.
	for _, e := range dr.run(15*time.Second, 0) {
		require.NotEqual(t, Switch, e.d.Action, "the policy went round again")
	}
}

// TestNoCandidatesGivesUpImmediately is the degenerate configuration. A policy
// with nowhere to go still has to say so once, because "there is nowhere to go"
// and "the path is fine" are different facts and a caller may act on the first.
func TestNoCandidatesGivesUpImmediately(t *testing.T) {
	dr := newDriver(t, Config{KeepAlive: bedKeepAlive, IdleTimeout: bedIdle}, candA)
	dr.run(time.Second, 123*time.Millisecond)
	got, ok := firstNot(dr.run(9*time.Second, 0), Stay)
	require.True(t, ok)
	assert.Equalf(t, GiveUp, got.d.Action, "%v", got.d)
	assert.Equalf(t, NoCandidates, got.d.Reason, "%v", got.d)
}

// TestOnePacketPerThresholdIsNotWorthCyclingFor is the failure that decided the
// rule above, replayed.
//
// The policy this replaced put a candidate back on the list once the connection
// had received something and then held quiet for a whole threshold. That is
// falsifiable by one packet, and a link that delivers exactly one just before
// each threshold expires falsifies it forever: measured against the shipped
// policy, 20 switches in 65 seconds, cycling 127.0.0.1:1002 and 127.0.0.1:1001
// and back with a round trip and a congestion-controller reset each way. That is
// worse than never switching at all, which is the standard this policy is held
// to.
//
// Nothing in a packet count separates that link from a healthy idle one. At this
// bed's 2s keep-alive a healthy idle connection delivers one answer per 2.05s
// and this driver delivers one per 4.07s, and a single lost keep-alive answer
// moves the healthy connection across any line drawn between the two. So the
// ambiguity is resolved as "stay where the walk left you": the list is walked
// once, and the standing answer afterwards is give-up.
//
// Three gaps are replayed, and the first of them is the boundary rather than a
// failure: at exactly the threshold no detection fires at all, because the
// packet lands in the same reading the silence would have been judged in. One
// poll interval past it is where the cycling started.
//
// Mutation: with the rule this replaced put back -- the outage clock, and the
// clearing of tried on any reading that is Alive a whole threshold after it --
// the 4.07s row fails with "a link delivering one packet per 4.07s drew 14
// switches in 65s: [127.0.0.1:1002 127.0.0.1:1001 ...]" and "still switching
// at 36.7s", and the 4.21s row draws 15. Those are this threshold's version of
// the 20 switches the same driver drew when the threshold was 3.05s; the count
// scales with the threshold and the behaviour does not.
func TestOnePacketPerThresholdIsNotWorthCyclingFor(t *testing.T) {
	for _, gap := range []time.Duration{bedThreshold, bedThreshold + poll, bedThreshold + 8*poll} {
		t.Run(gap.String(), func(t *testing.T) {
			dr := newDriver(t, bedConfig(candA, candB, candC), candA)
			evs := dr.run(65*time.Second, gap)

			// Two candidates besides the one it started on, so two switches is
			// the whole list. Sixty-five seconds is sixteen thresholds.
			assert.LessOrEqualf(t, countSwitches(evs), 2,
				"a link delivering one packet per %v drew %d switches in 65s: %v",
				gap, countSwitches(evs), switchesIn(evs))

			// And the last half of the run is settled: whatever it decided, it
			// decided in the first thirty seconds and is not still deciding.
			var tail []event
			for _, e := range evs {
				if e.at >= 35*time.Second {
					tail = append(tail, e)
				}
			}
			require.NotEmpty(t, tail)
			for _, e := range tail {
				require.NotEqualf(t, Switch, e.d.Action, "still switching at %v: %v", e.at, e.d)
			}

			if countSwitches(evs) == 0 {
				// At exactly the threshold nothing ever fires, so there is
				// nothing further to claim.
				return
			}
			// Having spent the list it says so, rather than going quiet as if
			// the path were fine. It says so in between the packets that still
			// arrive: those read Alive, which is what they are.
			var gaveUp bool
			for _, e := range tail {
				if e.d.Action == GiveUp && e.d.Reason == Exhausted {
					gaveUp = true
				}
			}
			assert.True(t, gaveUp, "the policy stopped answering once it ran out of candidates")
		})
	}
}

// TestACandidateStruckOffStaysOffForTheLifeOfTheConnection is the same rule from
// the other side: a candidate that answered for a while and then died does not
// buy the ones already tried another turn.
//
// The policy cannot tell a candidate that has recovered from one that has not,
// because it cannot observe a candidate it is not using at all -- that is the
// missing probe, named in the package comment -- so trying one again is
// speculation paid for with a round trip and a controller reset. Starting the
// walk over is a decision the caller makes by replacing the connection, and
// replacing the connection resets far more than a switch can.
//
// Mutation: with the same rule put back, this fails with "a candidate already
// found silent was tried again: switch (silent, quiet 4.06s of 4.05s) ->
// 127.0.0.1:1001" -- candA, struck off more than twenty seconds earlier -- and
// then with "the policy went round again".
func TestACandidateStruckOffStaysOffForTheLifeOfTheConnection(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.run(time.Second, 123*time.Millisecond)

	// candA dies and the policy moves to candB.
	got, ok := firstNot(dr.run(6*time.Second, 0), Stay)
	require.True(t, ok)
	require.Equal(t, candB, got.d.To)

	// candB delivers, and goes on delivering for far longer than a threshold.
	require.False(t, hasNonStay(dr.run(20*time.Second, 123*time.Millisecond)))

	// candB dies in its turn. candC is untried and is what it takes; candA is
	// not reconsidered however long candB worked for.
	got, ok = firstNot(dr.run(6*time.Second, 0), Stay)
	require.True(t, ok)
	assert.Equalf(t, candC, got.d.To, "a candidate already found silent was tried again: %v", got.d)

	// And with the list spent, the answer is give-up and stays give-up.
	for _, e := range dr.run(30*time.Second, 0) {
		require.NotEqualf(t, Switch, e.d.Action, "the policy went round again: %v", e.d)
	}
}

// TestKeepAliveOffMeansSilenceProvesNothing is the ambiguity the policy is
// required to encode as staying rather than to guess at.
//
// With KeepAlivePeriod at zero quic-go sends no keep-alive, so a connection
// whose application is quiet sends nothing, hears nothing, and looks exactly
// like a blackhole for as long as the application stays quiet. There is no
// signal at this boundary that separates the two -- the policy cannot see the
// application -- so it refuses to conclude anything.
//
// core/client never builds such a connection: it fills in 10s when the field is
// zero. This is a guard on a Config assembled by hand, and it is here because
// the alternative is a policy that switches paths on an idle user.
func TestKeepAliveOffMeansSilenceProvesNothing(t *testing.T) {
	dr := newDriver(t, Config{
		IdleTimeout: shippedIdle,
		Candidates:  []netip.AddrPort{candB, candC},
	}, candA)
	dr.run(time.Second, 123*time.Millisecond)
	evs := dr.run(120*time.Second, 0)
	for _, e := range evs {
		require.Equal(t, Stay, e.d.Action, "two minutes of silence decided something")
	}
	// And it stays for the stated reason rather than because the silence never
	// got long enough: two minutes is thirty times the threshold this
	// configuration would have had.
	assert.Equal(t, NoKeepAlive, evs[len(evs)-1].d.Reason)
}

// TestConnectionGoneGivesUpWithoutWalkingTheRest is measurement 5 spent.
//
// core/client.SwitchTo returns ErrNoConnection rather than a false success when
// the connection it is asked to move has already finished, and it does so
// precisely so that a selector can believe it. Nothing this policy decides can
// help a connection that has ended -- every remaining candidate is unreachable
// on it -- so walking the rest of the list one threshold at a time would be
// four seconds of nothing per candidate before reaching the same answer.
//
// Mutation: with SwitchFailed ignoring the outcome, this fails with "walked on
// to another candidate on a connection that had ended: switch (silent, quiet
// 6.04s of 4.05s) -> 127.0.0.1:1003".
func TestConnectionGoneGivesUpWithoutWalkingTheRest(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.run(time.Second, 123*time.Millisecond)

	got, ok := firstNot(dr.run(6*time.Second, 0), Stay)
	require.True(t, ok)
	require.Equal(t, candB, got.d.To)
	// The switch did not happen, so the connection is still where it was.
	dr.s.SwitchFailed(candB, ConnectionGone)
	dr.on = candA

	// candC is untried, and is not tried.
	next, ok := firstNot(dr.run(10*time.Second, 0), Stay)
	require.True(t, ok)
	assert.Equalf(t, GiveUp, next.d.Action,
		"walked on to another candidate on a connection that had ended: %v", next.d)
	assert.Equalf(t, Exhausted, next.d.Reason, "%v", next.d)
}

// TestARefusedCandidateIsStruckOffAndTheNextOneTried is the other outcome. A
// candidate the transport would not take says nothing about the connection, so
// the silence that provoked the switch is put back and the next reading reaches
// the same conclusion at once rather than after another threshold of waiting.
//
// Mutation: with SwitchFailed not restoring quietSince, the retry waits for
// the silence to build up again and this fails with '"2.1s" is not less than
// or equal to "20ms": the refusal cost a whole threshold instead of a
// reading'.
func TestARefusedCandidateIsStruckOffAndTheNextOneTried(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.run(time.Second, 123*time.Millisecond)

	got, ok := firstNot(dr.run(6*time.Second, 0), Stay)
	require.True(t, ok)
	require.Equal(t, candB, got.d.To)
	dr.s.SwitchFailed(candB, Refused)
	dr.on = candA
	refusedAt := dr.now

	next, ok := firstNot(dr.run(6*time.Second, 0), Stay)
	require.True(t, ok)
	assert.Equalf(t, Switch, next.d.Action, "%v", next.d)
	assert.Equal(t, candC, next.d.To)
	assert.LessOrEqual(t, next.at-refusedAt, poll,
		"the refusal cost a whole threshold instead of a reading")
}

// TestANewConnectionUnderneathRestartsTheClock covers the case a reconnecting
// client produces: it dials again, and the counters the policy is differencing
// belong to a connection that did not exist a moment ago.
//
// PacketsReceived falling is the only evidence of that available here -- a
// counter cannot fall on one connection -- and it has to be treated as a fresh
// start rather than as a delta, or the first reconnect after an outage either
// underflows the difference or fires on silence the new connection never had.
//
// Mutation: with the counter-regression case removed from Observe, this fails
// with "the new connection inherited the old one's silence: switch (silent,
// quiet 4.06s of 4.05s) -> 127.0.0.1:1002".
func TestANewConnectionUnderneathRestartsTheClock(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.run(time.Second, 123*time.Millisecond)

	// Nearly long enough to fire.
	evs := dr.run(bedThreshold-2*poll, 0)
	require.False(t, hasNonStay(evs))

	// A fresh connection: the counter starts again from nothing.
	dr.rx = 0
	if bad, ok := firstNot(dr.run(bedThreshold-2*poll, 0), Stay); ok {
		t.Fatalf("the new connection inherited the old one's silence: %v", bad.d)
	}
	// And it is judged from when it appeared, not from before.
	got, ok := firstNot(dr.run(time.Second, 0), Stay)
	require.True(t, ok, "the new connection was never judged at all")
	assert.Equal(t, Switch, got.d.Action)
}

// TestExhaustionEndsWithTheConnectionItWasAbout is the other half of a
// replacement, and the half the shipped policy got wrong.
//
// Having run out of candidates is a fact about one connection: it means every
// address was silent on the socket that connection held. On the socket that
// replaces it none of them has been tried, and answering GiveUp there is
// answering a question nobody asked -- the caller reconnected precisely because
// the policy told it to, and gets back a policy that has already given up.
//
// Both forms the Observation type can express are covered, because they are
// different code paths and a fix to one is not a fix to the other: a reading
// with Live false, which is what a reconnecting client shows between attempts,
// and a PacketsReceived that has fallen, which is what a client that dialled
// again between two readings shows.
//
// The connection replaced here is silent from its first reading. That is
// deliberate: it is the only shape in which the leak is visible on its own,
// because a replacement that delivers a packet first would also have cleared the
// old policy's outage rule and the two bugs would hide each other.
//
// Mutation: one branch at a time, each calling restart where it calls
// freshConnection. The Live-false branch fails the first subtest only and the
// counter-regression branch the second only, both with "the replacement
// connection inherited the old one's exhaustion: give-up (exhausted, quiet
// 14.98s of 4.05s)". Neither mutation is caught by the other subtest, which is
// why both are here.
func TestExhaustionEndsWithTheConnectionItWasAbout(t *testing.T) {
	// exhaust walks the whole candidate list and leaves the policy giving up.
	exhaust := func(t *testing.T, dr *driver) {
		t.Helper()
		dr.run(time.Second, 123*time.Millisecond)
		evs := dr.run(15*time.Second, 0)
		require.Equal(t, []Action{Stay, Switch, Stay, Switch, Stay, GiveUp}, actionsOf(evs),
			"the policy did not run out of candidates to begin with")
	}
	// walks is what a Selector with three candidates does on a connection that
	// goes silent: it tries the two it is not on, then gives up.
	walks := func(t *testing.T, dr *driver) {
		t.Helper()
		evs := dr.run(15*time.Second, 0)
		assert.Equalf(t, []netip.AddrPort{candB, candC}, switchesIn(evs),
			"the replacement connection inherited the old one's exhaustion: %v", evs[len(evs)-1].d)
	}

	t.Run("no connection, then a new one", func(t *testing.T) {
		dr := newDriver(t, bedConfig(candA, candB, candC), candA)
		exhaust(t, dr)

		// The client is between attempts, then dials again.
		dr.live = false
		dr.run(time.Second, 0)
		dr.live, dr.rx, dr.on = true, 0, candA
		walks(t, dr)
	})

	t.Run("the counter falls", func(t *testing.T) {
		dr := newDriver(t, bedConfig(candA, candB, candC), candA)
		exhaust(t, dr)

		// A different connection underneath, with no reading in between to say
		// so: the counter starting again from nothing is the whole evidence.
		dr.rx, dr.on = 0, candA
		walks(t, dr)
	})
}

// TestAMoveWeDidNotOrderRestartsTheClock covers a NAT rebinding. A QUIC
// connection with the path manager off follows the source address of the packets
// it accepts, so Current() can change without anybody deciding it should, and
// whatever silence had accumulated belonged to the address it left.
//
// Mutation: with the address-change case removed from Observe, this fails with
// "the rebinding inherited the old address's silence: switch (silent, quiet
// 4.06s of 4.05s) -> 127.0.0.1:1002".
func TestAMoveWeDidNotOrderRestartsTheClock(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.run(time.Second, 123*time.Millisecond)
	require.False(t, hasNonStay(dr.run(bedThreshold-2*poll, 0)))

	dr.on = candC
	if bad, ok := firstNot(dr.run(bedThreshold-2*poll, 0), Stay); ok {
		t.Fatalf("the rebinding inherited the old address's silence: %v", bad.d)
	}
}

// TestNoConnectionIsNotADeadPath is the reading a reconnecting client gives
// between attempts. There is nothing to observe and nothing to move, and the
// policy has to say which of those it is rather than counting the gap as
// silence.
func TestNoConnectionIsNotADeadPath(t *testing.T) {
	dr := newDriver(t, bedConfig(candA, candB, candC), candA)
	dr.run(time.Second, 123*time.Millisecond)

	dr.live = false
	for _, e := range dr.run(30*time.Second, 0) {
		require.Equal(t, Stay, e.d.Action)
		require.Equal(t, NoConnection, e.d.Reason)
	}

	// When one appears, it is judged from the moment it appeared.
	dr.live, dr.rx = true, 0
	if bad, ok := firstNot(dr.run(bedThreshold-2*poll, 0), Stay); ok {
		t.Fatalf("the reconnected client inherited the gap it spent disconnected: %v", bad.d)
	}
}

// TestReadingsOutOfOrderCannotManufactureSilence. Readings are expected in
// order; this says what happens when they are not, which is nothing.
func TestReadingsOutOfOrderCannotManufactureSilence(t *testing.T) {
	s := New(bedConfig(candB))
	base := time.Unix(0, 0)
	at := func(d time.Duration, rx uint64) Decision {
		return s.Observe(Observation{
			At: base.Add(d), On: candA, Live: true,
			Stats: pathstats.Stats{PacketsReceived: rx, SmoothedRTT: bedSRTT, RTTVariance: bedVar},
		})
	}
	require.Equal(t, Stay, at(0, 1).Action)
	require.Equal(t, Stay, at(10*time.Second, 2).Action)
	d := at(time.Second, 2)
	assert.Equal(t, Stay, d.Action)
	assert.Equal(t, time.Duration(0), d.Silence, "a clock that went backwards produced silence")
}

// fakePath is a Path that answers with whatever it was given.
type fakePath struct {
	stats pathstats.Stats
	live  bool
	addr  net.Addr
}

func (f fakePath) PathStats() (pathstats.Stats, bool) { return f.stats, f.live }
func (f fakePath) Current() net.Addr                  { return f.addr }

// TestSampleReadsThePathBoundary covers the adapter, which is the only place in
// this package that touches anything but numbers.
func TestSampleReadsThePathBoundary(t *testing.T) {
	now := time.Unix(0, 0)
	udp := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001}

	o, ok := Sample(now, fakePath{live: true, addr: udp, stats: pathstats.Stats{PacketsReceived: 7}})
	require.True(t, ok)
	assert.Equal(t, candA, o.On, "an IPv4 address must compare equal to the candidate written as IPv4")
	assert.True(t, o.Live)
	assert.Equal(t, uint64(7), o.Stats.PacketsReceived)

	// No connection: usable, and says so.
	o, ok = Sample(now, fakePath{live: false})
	require.True(t, ok)
	assert.False(t, o.Live)

	// A live connection whose address is not an address: not usable at all,
	// because it cannot be compared with any candidate.
	_, ok = Sample(now, fakePath{live: true, addr: nil})
	assert.False(t, ok)
}

// TestCandidatesInTheV4InV6FormAreStillMatched pins the normalisation in New.
//
// Everything a candidate is compared against has been unmapped, because it
// reached the policy through addrPort. A candidate list built the ordinary way
// -- net.ResolveUDPAddr(...).AddrPort(), or anything that went near a
// dual-stack socket -- has not been. Comparing the two forms is always false,
// so before this the address the connection sits on never matched the list,
// tried never recorded it, and the policy walked the same candidates for as
// long as the silence lasted: twenty-two switches in ninety seconds of one
// unbroken outage.
func TestCandidatesInTheV4InV6FormAreStillMatched(t *testing.T) {
	mapped := netip.AddrPortFrom(netip.AddrFrom16(candA.Addr().As16()), candA.Port())
	require.True(t, mapped.Addr().Is4In6(), "the fixture must be in the form the bug needs")

	// The connection reports the unmapped form; the config carries the mapped.
	dr := newDriver(t, bedConfig(mapped, candB), candA)
	evs := dr.run(90*time.Second, 0)

	var switches int
	for _, e := range evs {
		if e.d.Action == Switch {
			switches++
		}
	}
	assert.LessOrEqual(t, switches, 1,
		"the candidate the connection sits on was not recognised in its mapped form, so it kept being retried: %d switches", switches)
}
