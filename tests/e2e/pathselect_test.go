package e2e

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/core/v2/client"
	"github.com/chameleon-protocol/chameleon/core/v2/pathstats"
	"github.com/chameleon-protocol/chameleon/core/v2/selector"
	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// core/selector's policy against a real connection over a real impaired link.
//
// Everything the policy is made of is held by tables in core/selector, which is
// the point of it being a pure decision function. What tables cannot show is
// that the readings a live connection produces are the readings the policy was
// written for, and that a decision it makes can be carried out and helps. That
// is what this file is: one measured failure the policy has to act on, one
// measured non-failure it has to decline, and the switch actually performed.

// selectKeepAlive and selectIdle are this file's QUIC parameters.
//
// The keep-alive is the minimum core/client accepts, which is what makes the
// threshold four seconds rather than twelve and keeps these tests inside a
// reasonable running time. The idle timeout is the shipped default rather than
// pathfail's 4s minimum, and that difference is deliberate: pathfail was
// measuring how much sooner the detector fires than the stack gives up, so it
// wanted the stack to give up quickly. Here the connection has to survive the
// detection in order to be switched, so the stack must not have killed it first.
const (
	selectKeepAlive = 2 * time.Second
	selectIdle      = 30 * time.Second
)

// selectConfig is the policy's configuration for this bed, with the candidate
// list in the order a caller would supply it: the leg the client dialled first.
func selectConfig(paths *harness.MultiPath) selector.Config {
	return selector.Config{
		KeepAlive:   selectKeepAlive,
		IdleTimeout: selectIdle,
		Candidates:  paths.Candidates(),
	}
}

func selectOpts(seed uint64) harness.Options {
	return harness.Options{
		Seed: seed, Candidates: 2,
		Profile:         netem.RTT(50 * time.Millisecond),
		MaxIdleTimeout:  selectIdle,
		KeepAlivePeriod: selectKeepAlive,
	}
}

// interactiveLoad runs one small echo exchange every 50ms through the tunnel
// until the returned function is called.
//
// It is the load every gap in the sweep was measured under, and running the
// decline case without it would be measuring a different thing entirely: an idle
// connection on a rerouted path produces a receive gap of the keep-alive plus
// the new round trip, which is not the 1.019s the reroute was measured to
// produce and not what the policy is being asked to decline here.
//
// A failed exchange throws its tunnelled connection away and starts another,
// because a stream that times out says nothing about whether the path is
// finished -- that is the judgement under test, and the loader must not
// pre-empt it.
func interactiveLoad(t *testing.T, c client.Client, echo string) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := make([]byte, 100)
		resp := make([]byte, 100)
		var conn interface {
			io.ReadWriteCloser
			SetDeadline(time.Time) error
		}
		defer func() {
			if conn != nil {
				_ = conn.Close()
			}
		}()
		for {
			select {
			case <-done:
				return
			default:
			}
			if conn == nil {
				tcp, err := c.TCP(echo)
				if err != nil {
					time.Sleep(70 * time.Millisecond)
					continue
				}
				conn = tcp
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(req); err != nil {
				_ = conn.Close()
				conn = nil
				continue
			}
			if _, err := io.ReadFull(conn, resp); err != nil {
				_ = conn.Close()
				conn = nil
				continue
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done); wg.Wait() }) }
}

// selectRun is one decision, recorded with the moment it was taken and what
// carrying it out returned.
type selectRun struct {
	at  time.Duration
	d   selector.Decision
	err error
}

// drive polls the client every 20ms for d, feeds the policy, and carries out
// whatever it decides. Every decision that is not Stay is returned.
//
// The polling interval is the one the measurements were taken at, and the whole
// reading comes through selector.Sample and the selector.Path interface: the
// client is passed as that interface and nothing else, so what this exercises is
// the boundary the package actually declares rather than a convenience the test
// arranged.
func drive(t *testing.T, env *harness.Env, sel *selector.Selector, dur time.Duration) []selectRun {
	t.Helper()
	path, ok := env.Client.(selector.Path)
	require.True(t, ok, "a core client must satisfy the policy's input boundary")
	pc, ok := env.Client.(client.PathController)
	require.True(t, ok)

	var out []selectRun
	start := time.Now()
	for at := time.Duration(0); at < dur; at = time.Since(start) {
		time.Sleep(20 * time.Millisecond)
		o, usable := selector.Sample(time.Now(), path)
		if !usable {
			continue
		}
		d := sel.Observe(o)
		if d.Action == selector.Stay {
			continue
		}
		r := selectRun{at: time.Since(start), d: d}
		if d.Action == selector.Switch {
			r.err = pc.SwitchTo(net.UDPAddrFromAddrPort(d.To))
			if r.err != nil {
				sel.SwitchFailed(d.To, switchOutcome(r.err))
			}
		}
		t.Logf("t=+%v %v err=%v", r.at.Round(time.Millisecond), d, r.err)
		out = append(out, r)
	}
	return out
}

// switchOutcome is the mapping core/selector documents and deliberately does not
// import core/client to perform. It is one line, and it is the only thing the
// wiring has to know that the policy does not.
func switchOutcome(err error) selector.Outcome {
	if errors.Is(err, client.ErrNoConnection) {
		return selector.ConnectionGone
	}
	return selector.Refused
}

// TestSelectorLeavesABlackholedCandidate is the measured failure, decided and
// acted on end to end.
//
// Only the candidate the connection is using is blackholed, which is the
// scenario a Selector exists for and the one a whole-link fault cannot state:
// the other candidate is untouched and reaches the same server, so a connection
// that genuinely moves recovers and one that does not, does not.
//
// Mutation: with the SwitchTo call removed from drive, so the policy decides
// and nothing carries it out, this fails twice -- "the policy decided more
// than once in twelve seconds", with the same decision repeated at 4.096s and
// 8.198s, and then "the connection did not recover on the candidate it moved
// to". Both halves are the point. The connection stays on the blackholed leg
// and dies there, and the repetition is the case Observe's doc names: a caller
// that neither carries a decision out nor reports it back leaves the policy
// reading the disagreement as a rebinding, which restarts the clock and
// forgives the path. That now costs one repetition per candidate rather than
// one every threshold forever, and the connection is dead either way.
func TestSelectorLeavesABlackholedCandidate(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live connection across a blackhole and a switch")
	}
	env := harness.New(t, selectOpts(500))
	legs := env.Paths.Legs
	env.Ctrl.SetFor(legs[0].Key(), netem.RTT(50*time.Millisecond))
	env.Ctrl.SetFor(legs[1].Key(), netem.RTT(50*time.Millisecond))
	require.NoError(t, env.Echo(probeTimeout))
	require.Zero(t, legs[1].Stats().FromClient, "leg 1 must be idle before the switch")

	stop := interactiveLoad(t, env.Client, env.TCPEcho)
	defer stop()

	sel := selector.New(selectConfig(env.Paths))
	// Three seconds of health first. Without it the policy's first reading is
	// also its first judgement, and a run that decided correctly for the wrong
	// reason would look the same as this one.
	require.Empty(t, drive(t, env, sel, 3*time.Second),
		"the policy decided something on a healthy connection")

	env.Ctrl.SetFor(legs[0].Key(), netem.Blocked())
	runs := drive(t, env, sel, 12*time.Second)

	require.NotEmpty(t, runs, "the policy never noticed a blackholed candidate")
	first := runs[0]
	assert.Equal(t, selector.Switch, first.d.Action, "%v", first.d)
	assert.Equal(t, legs[1].Key(), first.d.To, "the untouched candidate is the one to take")
	require.NoError(t, first.err, "the switch the policy asked for could not be carried out")

	// It fired once. A policy that re-decided every reading would have spent
	// both candidates inside the first hundred milliseconds.
	assert.Len(t, runs, 1, "the policy decided more than once in twelve seconds")

	// And the decision was worth making: the connection works again, on the leg
	// it moved to, without having been rebuilt.
	require.NoError(t, env.Echo(probeTimeout), "the connection did not recover on the candidate it moved to")
	assert.Positive(t, legs[1].Stats().FromClient, "leg 1 carried nothing after the switch")

	// The detection was quicker than the stack's own verdict, which is the
	// reason for having a policy at all: at this bed's 30s idle timeout the
	// connection was still alive to be moved.
	assert.Less(t, first.at, 5*time.Second, "detection was slower than every run measured")
}

// TestSelectorDeclinesAPathThatMerelyGotSlower is the measured non-failure.
//
// A step from 50ms to a 1s round trip is a reroute, not a block: the path still
// delivers, the application never sees a failure, and switching off it is
// strictly worse than staying -- the candidate switched to would have to be
// re-measured from scratch, and the measurements have a case where that costs
// the connection a 20ms path for a 487ms one permanently.
//
// The load matters and is why this test runs one. The 1.019s gap this declines
// is the gap an application-driven connection produces on a rerouted path; an
// idle connection on the same path produces the keep-alive interval instead, and
// declining that would be a different claim.
//
// Mutation: with the policy switching at an eighth of its threshold this fails
// with "a path that merely got slower was abandoned at 518ms: switch (silent,
// quiet 518ms of 4.055s)" -- an eighth of a threshold that had not yet grown.
//
// A sixth of the threshold does not break it, and why is worth recording,
// because it is the round-trip term earning its place. Logging every reading
// of that run: the threshold climbs from 4.055s to 6.58s as SmoothedRTT tracks
// the step, while the worst gap the rerouted path produces is 1.054s. The
// policy grew more patient exactly as the path got slower, which is the
// behaviour a fixed threshold cannot have.
func TestSelectorDeclinesAPathThatMerelyGotSlower(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live connection for fifteen seconds")
	}
	env := harness.New(t, selectOpts(501))
	legs := env.Paths.Legs
	env.Ctrl.SetFor(legs[0].Key(), netem.RTT(50*time.Millisecond))
	env.Ctrl.SetFor(legs[1].Key(), netem.RTT(50*time.Millisecond))
	require.NoError(t, env.Echo(probeTimeout))

	stop := interactiveLoad(t, env.Client, env.TCPEcho)
	defer stop()

	sel := selector.New(selectConfig(env.Paths))
	require.Empty(t, drive(t, env, sel, 3*time.Second))

	env.Ctrl.SetFor(legs[0].Key(), netem.RTT(time.Second).Named("rtt-step-1s"))
	runs := drive(t, env, sel, 12*time.Second)

	if len(runs) > 0 {
		t.Fatalf("a path that merely got slower was abandoned at %v: %v",
			runs[0].at.Round(time.Millisecond), runs[0].d)
	}

	// The path really was still working, from netem's own counters and from the
	// application alike. Without this the decline above could be the policy
	// declining to notice a link that had died.
	require.NoError(t, env.Echo(probeTimeout), "the rerouted path was not actually working")
	assert.Zero(t, legs[1].Stats().FromClient, "the connection moved without the policy saying so")
	assert.Positive(t, env.Ctrl.StatsFor(legs[0].Key()).Down.Out,
		"the rerouted leg delivered nothing; the case did not run")
}

// TestSelectorThresholdCoversTheMeasuredOne is a drift guard between two numbers
// that were arrived at independently: the threshold pathfail_test.go recommends
// from its sweep, and the one core/selector computes.
//
// It is not a tautology -- neither reads the other -- and it is not an equality
// either, because core/selector adds two terms selectorSilence's own comment says
// a Selector has to add. What has to hold is the direction: the policy must never
// be quicker to condemn a path than the value the sweep measured to be safe.
//
// Mutation: with core/selector's silenceSlack at zero, every row fails -- the
// pathfail bed with '"2.05s" is not greater than or equal to "3s": the policy
// condemns a path sooner than the sweep measured to be safe', and the shipped
// defaults with 10.05s against 11s.
func TestSelectorThresholdCoversTheMeasuredOne(t *testing.T) {
	cases := []struct {
		name            string
		keepAlive, idle time.Duration
	}{
		{"pathfail bed", pathfailKeepAlive, pathfailIdleTimeout},
		{"shipped defaults", shippedKeepAlive, shippedIdleTimeout},
		{"this file's bed", selectKeepAlive, selectIdle},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := selectorSilence(c.keepAlive, c.idle)
			got := selector.Threshold(
				selector.Config{KeepAlive: c.keepAlive, IdleTimeout: c.idle},
				statsAt(50*time.Millisecond, 10*time.Millisecond))
			t.Logf("%s: the sweep recommends %v, the policy computes %v", c.name, want, got)
			assert.GreaterOrEqual(t, got, want,
				"the policy condemns a path sooner than the sweep measured to be safe")
		})
	}
}

// statsAt is a reading of a path with these round trips and nothing else, which
// is all Threshold reads.
func statsAt(srtt, rttvar time.Duration) pathstats.Stats {
	return pathstats.Stats{SmoothedRTT: srtt, RTTVariance: rttvar}
}
