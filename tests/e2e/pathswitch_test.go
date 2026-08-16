package e2e

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/core/v2/client"
	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// What core/client.PathController promises, held against a real connection.
//
// A switch is three things -- move the address, throw away what the old path
// taught the connection, put the negotiated congestion controller back -- and
// each of the three has a test here that fails when only that one is removed.
// The failures were produced by removing them, and each test's comment says
// what the removal looked like.

// load runs a bulk transfer through the tunnel until the returned function is
// called, and reports how many bytes have come back. A switch is only
// measurable under load: the state it resets is state the connection derived
// from packets in flight.
func load(t *testing.T, c client.Client, echo string) (bytes func() uint64, stop func()) {
	t.Helper()
	conn, err := c.TCP(echo)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(120*time.Second)))

	var echoed atomic.Uint64
	done := make(chan struct{})
	go func() {
		chunk := make([]byte, 32<<10)
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := conn.Read(buf)
			echoed.Add(uint64(n))
			if err != nil {
				return
			}
		}
	}()
	var once atomic.Bool
	return echoed.Load, func() {
		if once.CompareAndSwap(false, true) {
			close(done)
			_ = conn.Close()
		}
	}
}

// goodputOver is the payload rate over d, measured from a running load.
func goodputOver(bytes func() uint64, d time.Duration) float64 {
	from := bytes()
	time.Sleep(d)
	return float64(bytes()-from) / d.Seconds()
}

// TestSwitchToMovesTheConnection is the first of the three steps: the
// connection's destination.
//
// Killing the old candidate after the switch is what makes the assertion mean
// something. Both legs reach the same server, so a switch that did nothing at
// all would still pass an echo; only a connection that has genuinely left leg 0
// survives leg 0 being blackholed.
//
// Mutation: with the SetRemoteAddr call commented out of SwitchTo, leg 1 never
// sees a packet -- '"0" is not positive: leg 1 must carry the client's packets
// after the switch' -- and the echo after the blackhole fails with
// "connection closed: timeout: no recent network activity".
func TestSwitchToMovesTheConnection(t *testing.T) {
	env := harness.New(t, harness.Options{Seed: 21, Candidates: 2})
	legs := env.Paths.Legs
	env.Ctrl.SetFor(legs[0].Key(), netem.Clean())
	env.Ctrl.SetFor(legs[1].Key(), netem.Clean())
	require.NoError(t, env.Echo(probeTimeout))
	require.Zero(t, legs[1].Stats().FromClient, "leg 1 must be idle before the switch")

	pc, ok := env.Client.(client.PathController)
	require.True(t, ok, "a core client must be a PathController")
	require.Equal(t, legs[0].Addr().String(), pc.Current().String())

	require.NoError(t, pc.SwitchTo(legs[1].Addr()))
	assert.Equal(t, legs[1].Addr().String(), pc.Current().String())
	require.NoError(t, env.Echo(probeTimeout))

	// The client now sends through leg 1, and the server, which follows the
	// source address of what it accepts, answers through it.
	assert.Positive(t, legs[1].Stats().FromClient, "leg 1 must carry the client's packets after the switch")
	assert.Positive(t, legs[1].Stats().FromServer, "the server's return path must have followed onto leg 1")

	// The old candidate goes away entirely. A connection still using it dies at
	// the idle timeout instead of answering.
	env.Ctrl.SetFor(legs[0].Key(), netem.Blocked())
	require.NoError(t, env.Echo(probeTimeout), "the connection must not depend on the candidate it left")
}

// TestSwitchToOnAReconnectingClient covers the wrapper rather than the
// connection. A reconnecting client is what the app builds, so it is what a
// selector will actually hold, and it has to forward a switch to whichever
// connection is current rather than to the one it was holding when the selector
// first asked.
//
// Mutation: making reconnectableClientImpl.SwitchTo return ErrNoConnection
// without forwarding fails here with "no connection to switch", and fails
// nowhere else in the suite -- every other case here holds a plain client.
func TestSwitchToOnAReconnectingClient(t *testing.T) {
	env := harness.New(t, harness.Options{Seed: 25, Candidates: 2, Reconnect: true})
	legs := env.Paths.Legs
	env.Ctrl.SetFor(legs[0].Key(), netem.Clean())
	env.Ctrl.SetFor(legs[1].Key(), netem.Clean())
	require.NoError(t, env.Echo(probeTimeout))

	pc, ok := env.Client.(client.PathController)
	require.True(t, ok, "a reconnectable client must be a PathController")
	require.NoError(t, pc.SwitchTo(legs[1].Addr()))
	assert.Equal(t, legs[1].Addr().String(), pc.Current().String())
	require.NoError(t, env.Echo(probeTimeout))
	assert.Positive(t, legs[1].Stats().FromClient, "the switch must have reached the connection underneath")
}

// TestSwitchToResetsTheRoundTripEstimate is the second step, and the one that
// is silent when it is missing.
//
// quic-go's minimum round trip is a lifetime minimum: it can fall but never
// rise. Moving to a slower candidate without resetting it therefore leaves the
// connection permanently believing in the old path's delay, and Brutal sizes
// its congestion window from that belief -- so the window stays sized for a
// 20ms path while the packets take 200ms, and the sender is window-bound at a
// fraction of the rate it declared.
//
// The expected value is the delay this bed imposes on leg 1, not anything read
// out of the code under test.
//
// Mutation: with the ResetPathState call commented out of SwitchTo, the
// estimate stays on the candidate the connection left -- '"5.401583ms" is not
// greater than "100ms"' -- and the client offers 461751 bytes to the new
// candidate over the two seconds measured here, against 4172611 with the reset
// in place. That is not a slow start it recovers from; a lifetime minimum has
// no way back up.
func TestSwitchToResetsTheRoundTripEstimate(t *testing.T) {
	const declared = 2 << 20
	const fastLeg = 5 * time.Millisecond
	const legDelay = 200 * time.Millisecond
	env := harness.New(t, harness.Options{
		Seed: 22, Candidates: 2,
		Profile:        netem.RTT(fastLeg),
		MaxIdleTimeout: 10 * time.Second,
		Bandwidth:      harness.Bandwidth{BytesPerSec: declared},
	})
	legs := env.Paths.Legs
	env.Ctrl.SetFor(legs[0].Key(), netem.RTT(fastLeg))
	env.Ctrl.SetFor(legs[1].Key(), netem.RTT(legDelay))

	_, stop := load(t, env.Client, env.TCPEcho)
	defer stop()
	stats := env.Client.(client.PathStatsProvider)

	// Settle on leg 0 so that there is a fast path's minimum to carry across.
	time.Sleep(time.Second)
	before, ok := stats.PathStats()
	require.True(t, ok)
	require.Less(t, before.MinRTT, legDelay/4,
		"the fast candidate must have been measured before the switch means anything")

	require.NoError(t, env.Client.(client.PathController).SwitchTo(legs[1].Addr()))

	// Three round trips of the new path. The first sample lands after one and a
	// half of them on this bed; being generous costs nothing, because the
	// failure this guards is permanent rather than slow.
	time.Sleep(3 * legDelay)
	after, ok := stats.PathStats()
	require.True(t, ok)
	assert.Greater(t, after.MinRTT, legDelay/2,
		"the connection must have re-measured the candidate it moved to, not kept the old one's %v", before.MinRTT)

	// And the window that estimate feeds has to let the connection use the new
	// path. Held to leg 0's minimum the window is 2 x declared x 5ms = 40kB
	// outstanding, which over a 200ms round trip is a ceiling of 200 kB/s
	// however much the sender has to send.
	//
	// What is counted is what the client offers to leg 1, not what comes back
	// through the tunnel: a single echoed stream over a 400ms application round
	// trip is bound by the stream's receive window long before it is bound by
	// anything a path switch touches, and measures 228 kB/s either way. The
	// bound this test is about is on the wire.
	const measure = 2 * time.Second
	up0 := env.Ctrl.StatsFor(legs[1].Key()).Up
	time.Sleep(measure)
	offered := env.Ctrl.StatsFor(legs[1].Key()).Up.InBytes - up0.InBytes
	t.Logf("offered to the new candidate over %v: %d bytes, against a declared %d B/s",
		measure, offered, declared)
	assert.Greater(t, offered, uint64(0.35*declared*measure.Seconds()),
		"the connection could not use the candidate it moved to")
}

// TestSwitchToKeepsTheNegotiatedCongestionController is the third step.
//
// Resetting the path state installs quic-go's default Reno sender, because that
// is what the internal migration paths want. A switch that stops there has
// silently replaced the controller the handshake negotiated with one that halves
// its window for every loss -- at the moment the connection is being moved,
// which is the moment a path is least likely to be clean.
//
// The lossy leg is what separates the two: Brutal sends the declared rate
// through 10% loss, a loss-based controller does not.
//
// Mutation: commenting out the installCongestionControl call in SwitchTo drops
// goodput on leg 1 from 1943806 B/s to 190866 B/s; moving that call above
// ResetPathState instead, so the reset overwrites what it installed, gives
// 243150 B/s. Both are the default Reno sender meeting 10% loss.
func TestSwitchToKeepsTheNegotiatedCongestionController(t *testing.T) {
	if testing.Short() {
		t.Skip("measures a rate over seconds")
	}
	const declared = 2 << 20
	env := harness.New(t, harness.Options{
		Seed: 23, Candidates: 2,
		Profile:        netem.RTT(20 * time.Millisecond),
		MaxIdleTimeout: 10 * time.Second,
		Bandwidth:      harness.Bandwidth{BytesPerSec: declared},
	})
	legs := env.Paths.Legs
	lossy := netem.RTT(20 * time.Millisecond).WithLoss(0.10).Named("rtt20ms+loss10%")
	env.Ctrl.SetFor(legs[0].Key(), netem.RTT(20*time.Millisecond))
	env.Ctrl.SetFor(legs[1].Key(), lossy)

	bytes, stop := load(t, env.Client, env.TCPEcho)
	defer stop()
	time.Sleep(time.Second)

	require.NoError(t, env.Client.(client.PathController).SwitchTo(legs[1].Addr()))
	time.Sleep(500 * time.Millisecond) // let the new path take over
	got := goodputOver(bytes, 3*time.Second)
	t.Logf("goodput on the lossy candidate after the switch: %.0f B/s of a declared %d", got, declared)
	assert.Greater(t, got, 0.5*declared,
		"a rate-based controller sends the declared rate through this loss; a loss-based one does not")
}

// TestSwitchToOnADeadConnection is the call a Selector makes first, on exactly
// the connection it suspects is dead.
//
// clientImpl.conn is assigned once, at the end of connect, and never cleared,
// so the `c.conn == nil` guard SwitchTo rested on cannot fire on a plain
// client: before this test a closed connection took the switch and reported
// success, and Current() then named the address it claimed to have moved to.
// A selector reading that believes it has recovered and stops trying.
//
// Mutation: with the connection-liveness checks removed from SwitchTo this
// fails with 'Expected error with "no connection to switch" in chain but got
// nil', and the Current() assertion below with 'expected: "127.0.0.1:55706"
// actual: "127.0.0.1:56752"' -- the switch having moved the address of a
// connection that no longer exists.
func TestSwitchToOnADeadConnection(t *testing.T) {
	env := harness.New(t, harness.Options{Seed: 26, Candidates: 2})
	legs := env.Paths.Legs
	require.NoError(t, env.Echo(probeTimeout))

	pc, ok := env.Client.(client.PathController)
	require.True(t, ok)
	before := pc.Current().String()
	require.NoError(t, env.Client.Close())

	assert.ErrorIs(t, pc.SwitchTo(legs[1].Addr()), client.ErrNoConnection)
	assert.Equal(t, before, pc.Current().String(),
		"a refused switch reported the address it refused to move to")
}

// TestSwitchToWithNothingToSwitch is the state a reconnecting client is in
// between attempts. Asking it to move must not be the thing that dials.
func TestSwitchToWithNothingToSwitch(t *testing.T) {
	env := harness.New(t, harness.Options{Seed: 24, Candidates: 2})
	pc, ok := env.Client.(client.PathController)
	require.True(t, ok)
	assert.Error(t, pc.SwitchTo(nil), "a nil address is not an address")
	assert.Equal(t, env.Paths.Legs[0].Addr().String(), pc.Current().String(),
		"a rejected switch must leave the connection where it was")
}
