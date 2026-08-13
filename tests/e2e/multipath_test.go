package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// These tests exercise the two capabilities a multi-candidate criterion needs:
// impairing one candidate without touching the others, and reaching one server
// at several addresses. Everything about P1 -- how fast a failover is, whether
// the connection survives it, whether an on-path attacker can move the return
// path -- is a statement about several candidates at once, and none of it could
// be written down before these existed.

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func TestMultiPathLegsAreReachableAndIndependent(t *testing.T) {
	env := harness.New(t, harness.Options{Seed: 1, Candidates: 3})
	legs := env.Paths.Legs
	for i, leg := range legs {
		env.Ctrl.SetFor(leg.Key(), netem.Clean())
		t.Logf("candidate %d: %s", i, leg.Addr())
	}
	require.NoError(t, env.Echo(probeTimeout))

	// The client dials leg 0, so that is the only leg carrying anything. The
	// others are reachable but unused, which is exactly the state a candidate
	// set is in before a Selector picks a second one.
	assert.Positive(t, legs[0].Stats().FromClient)
	assert.Positive(t, legs[0].Stats().FromServer)
	assert.Zero(t, legs[1].Stats().FromClient)
	assert.Zero(t, legs[2].Stats().FromClient)

	// The counters at the netem layer agree, and they are per candidate: the
	// live leg moved bytes, the idle ones moved none.
	assert.Positive(t, env.Ctrl.StatsFor(legs[0].Key()).Up.Out)
	assert.Zero(t, env.Ctrl.StatsFor(legs[1].Key()).Up.Out)

	// Killing a candidate the client is not using must not disturb the one it
	// is. Before per-candidate impairment this could not even be attempted:
	// there was one profile for the whole socket.
	env.Ctrl.SetFor(legs[1].Key(), netem.Blocked())
	env.Ctrl.SetFor(legs[2].Key(), netem.Loss(0.5))
	require.NoError(t, env.Echo(probeTimeout), "impairing an idle candidate must not touch the live one")
}

func TestBlackholingTheCandidateInUseStrandsTheClient(t *testing.T) {
	// The honest record of where P1 stands. Two candidates are healthy and one
	// is dead, and the client dies anyway, because nothing in the stack today
	// looks at the healthy ones: core/client takes a single ServerAddr.
	//
	// It runs rather than skips because it is the control for
	// TestFailoverToLivingCandidate below: the same setup, the same cut, and the
	// difference between them is exactly what the Selector has to deliver.
	if testing.Short() {
		t.Skip("waits out the QUIC idle timeout")
	}
	env := harness.New(t, harness.Options{
		Seed: 2, Candidates: 3,
		MaxIdleTimeout: 4 * time.Second,
	})
	legs := env.Paths.Legs
	for _, leg := range legs {
		env.Ctrl.SetFor(leg.Key(), netem.Clean())
	}
	require.NoError(t, env.Echo(probeTimeout))

	env.Ctrl.SetFor(legs[0].Key(), netem.Blocked())
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = env.Echo(2 * time.Second); lastErr != nil {
			break
		}
	}
	require.Error(t, lastErr, "the client should have died with its only candidate")
	t.Logf("client died with candidates 1 and 2 healthy: %v", lastErr)

	// The other two legs were never tried. That is the gap, stated as a number.
	assert.Zero(t, legs[1].Stats().FromClient)
	assert.Zero(t, legs[2].Stats().FromClient)
	assert.Positive(t, env.Ctrl.StatsFor(legs[0].Key()).Up.Dropped)
}

func TestFailoverToLivingCandidate(t *testing.T) {
	t.Skip("no Selector yet: core/client dials a single ServerAddr, so nothing " +
		"can move the connection to another candidate. This is the P1b landing " +
		"point -- the setup below is the acceptance case, and it should start " +
		"passing when extras/realm/selector.go exists.")

	env := harness.New(t, harness.Options{
		Seed: 3, Candidates: 3,
		MaxIdleTimeout: 4 * time.Second,
	})
	legs := env.Paths.Legs
	for _, leg := range legs {
		env.Ctrl.SetFor(leg.Key(), netem.RTT(50*time.Millisecond))
	}
	require.NoError(t, env.Echo(probeTimeout))

	// Kill the candidate in use and one spare, leaving exactly one way through.
	cut := time.Now()
	env.Ctrl.SetFor(legs[0].Key(), netem.Blocked())
	env.Ctrl.SetFor(legs[1].Key(), netem.Blocked())

	var gap time.Duration
	require.True(t, waitFor(t, 10*time.Second, func() bool {
		if err := env.Echo(2 * time.Second); err != nil {
			return false
		}
		gap = time.Since(cut)
		return true
	}), "the connection must survive on the candidate that is still up")

	t.Logf("failover gap: %v", gap.Round(time.Millisecond))
	assert.Positive(t, env.Ctrl.StatsFor(legs[2].Key()).Up.Out,
		"the traffic must actually have moved to the surviving candidate")
}

// TestUnfilteredPathFollowIsHijackable records what the server does today when
// an on-path attacker rewrites the source address of genuine, unmodified client
// packets: it moves the whole return path to the new address, for the cost of a
// handful of packets and no cryptography at all.
//
// This is not an assertion that the behaviour is right. It is the opposite: it
// is the evidence that the PathChangeFilter in the P1 design has a reason to
// exist, pinned down so that "the server follows source addresses
// unconditionally" stops being a sentence in a document and becomes a number a
// test prints. When the filter lands, this test inverts -- the assertions here
// become the unfiltered control case and a filtered twin asserts the server
// stays put.
//
// The mechanism, verified in the fork at connection.go:1295-1298: with
// DisablePathManager set (core/server/server.go:66), a 1-RTT packet that
// decrypts and arrives from an address other than the current remote goes
// straight to ChangeRemoteAddr. There is no PATH_CHALLENGE, because
// DisablePathManager is what turns it off, and there is no check that the
// packet is the highest-numbered one either -- the branch two dozen lines below
// at :1322 has that check and this one does not.
//
// One packet is enough to move the server; this test does not try to prove that
// with a count of one, because the server reads a batch of datagrams before it
// sends, so the client's own next genuine packet usually drags it back within
// the same batch. That is not a mitigation, it is the flap the design warns
// about, and RestoringTheSourceMovesItBack below is the same evidence read the
// other way round.
func TestUnfilteredPathFollowIsHijackable(t *testing.T) {
	env := harness.New(t, harness.Options{Seed: 4, Candidates: 2})
	victim, attacker := env.Paths.Legs[0], env.Paths.Legs[1]
	env.Ctrl.SetFor(victim.Key(), netem.Clean())
	env.Ctrl.SetFor(attacker.Key(), netem.Clean())

	require.NoError(t, env.Echo(probeTimeout))
	require.Zero(t, attacker.Stats().FromServer,
		"the server has never sent anything to the attacker's address")

	// Nothing is forged, replayed or modified here, and the attacker does not
	// need to understand a single byte: these are the client's own packets, put
	// on the wire from a different source address.
	victim.RewriteSourceTo(attacker)
	var cost uint64
	require.True(t, waitFor(t, 10*time.Second, func() bool {
		_ = env.Echo(2 * time.Second)
		if attacker.Stats().FromServer == 0 {
			return false
		}
		cost = victim.Stats().Rewritten
		return true
	}), "the server did not move; if this fails the fork's path handling changed")
	t.Logf("the server's return path moved after %d rewritten packets", cost)
	assert.LessOrEqual(t, cost, uint64(16),
		"the attack should cost a handful of packets, not a session's worth")

	// Held, not just touched: the return path stays on the attacker and the
	// victim's leg goes quiet. Nothing at either endpoint reports anything wrong
	// -- the client accepts datagrams from the new address because RFC 9000 lets
	// only the client migrate, so quic-go returns before it ever compares the
	// source (connection.go:1290).
	require.NoError(t, env.Echo(probeTimeout))
	settled, held := victim.Stats().FromServer, attacker.Stats().FromServer
	for i := 0; i < 3; i++ {
		require.NoError(t, env.Echo(probeTimeout), "the hijack is invisible to both endpoints")
	}
	assert.Equal(t, settled, victim.Stats().FromServer,
		"the server stopped answering on the address the client is dialling")
	assert.Greater(t, attacker.Stats().FromServer, held,
		"the return path stayed on the attacker's address")
	assert.Positive(t, attacker.Stats().ToClient)

	// And it goes back the moment the source addresses do, with no more
	// ceremony than it took to leave. Whatever source the server saw last is
	// where it answers -- which is why ordinary reordering between two live
	// candidates makes it oscillate.
	t.Run("RestoringTheSourceMovesItBack", func(t *testing.T) {
		victim.RewriteSourceTo(nil)
		back := victim.Stats().FromServer
		require.True(t, waitFor(t, 10*time.Second, func() bool {
			_ = env.Echo(2 * time.Second)
			return victim.Stats().FromServer > back
		}), "the server should follow the client's real address straight back")
		t.Logf("after %d rewritten packets in total: victim %d, attacker %d",
			victim.Stats().Rewritten, victim.Stats().FromServer, attacker.Stats().FromServer)
	})
}
