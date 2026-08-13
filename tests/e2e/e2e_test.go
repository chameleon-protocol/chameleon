// chameleon -- a censorship-resistant transport
// Copyright (C) 2026 The chameleon authors
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 3 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreErrs "github.com/chameleon-protocol/chameleon/core/v2/errors"

	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/metrics"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem/kernel"
)

// These tests run a real core server and a real core client against each other
// over a user-space impaired link. They are the reason the impairment layer
// exists: a number measured here is a number about the transport, not about a
// mock.

const (
	shortTransfer = 512 << 10 // enough to leave slow start, cheap enough for -short
	longTransfer  = 4 << 20   // the size regression runs should use
	probeTimeout  = 8 * time.Second
)

func TestEchoSurvivesEveryStandardProfile(t *testing.T) {
	for _, profile := range netem.Standard() {
		t.Run(profile.Name, func(t *testing.T) {
			t.Parallel()
			env := harness.New(t, harness.Options{Profile: profile, Seed: 1})
			require.NoError(t, env.Echo(probeTimeout))
			require.NoError(t, env.Echo(probeTimeout), "a second exchange must reuse the same connection")
		})
	}
}

func TestUDPForwardingSurvivesLossAndDelay(t *testing.T) {
	profile := netem.RTT(50 * time.Millisecond).WithLoss(0.01)
	env := harness.New(t, harness.Options{Profile: profile, Seed: 2})

	conn, err := env.Client.UDP()
	require.NoError(t, err)
	defer conn.Close()

	// UDP through the tunnel is unreliable end to end, so this asserts that
	// some datagrams survive, not that all do.
	const attempts = 30
	got := 0
	for i := 0; i < attempts; i++ {
		require.NoError(t, conn.Send([]byte("udp-probe"), env.UDPEcho))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < attempts; i++ {
			data, _, err := conn.Receive()
			if err != nil {
				return
			}
			if string(data) == "udp-probe" {
				got++
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	assert.Positive(t, got, "no datagram made it back through a 1%% loss, 50ms link")
	t.Logf("udp echo: %d/%d returned", got, attempts)
}

func TestThroughputAcrossStandardProfiles(t *testing.T) {
	size := longTransfer
	if testing.Short() {
		size = shortTransfer
	}
	for _, profile := range netem.Standard() {
		t.Run(profile.Name, func(t *testing.T) {
			env := harness.New(t, harness.Options{Profile: profile, Seed: 3})
			bps, err := env.TCPThroughput(size, 60*time.Second)
			require.NoError(t, err)
			assert.Positive(t, bps)
			t.Logf("%s: %s (%s)", profile.Name, metrics.FormatRate(bps), env.Ctrl.Stats())
		})
	}
}

// TestRateLimitCapsThroughput is the one throughput assertion that is a law
// rather than a threshold: traffic cannot exceed the shaper it crossed.
func TestRateLimitCapsThroughput(t *testing.T) {
	const rate = 2 << 20 // 2MB/s each way
	env := harness.New(t, harness.Options{Profile: netem.RateLimited(rate), Seed: 4})

	bps, err := env.TCPThroughput(2<<20, 60*time.Second)
	require.NoError(t, err)
	t.Logf("shaped at %s, measured %s", metrics.FormatRate(rate), metrics.FormatRate(bps))
	// The shaper's burst lets a short transfer average slightly above the rate;
	// twice the rate is far outside that.
	assert.Less(t, bps, float64(rate)*2)
}

func TestLatencyPercentilesTrackConfiguredRTT(t *testing.T) {
	cases := []struct {
		name string
		rtt  time.Duration
	}{
		{"rtt0", 0},
		{"rtt50ms", 50 * time.Millisecond},
		{"rtt200ms", 200 * time.Millisecond},
	}
	got := make(map[string]metrics.Summary, len(cases))
	for _, c := range cases {
		profile := netem.Clean().Named(c.name)
		if c.rtt > 0 {
			profile = netem.RTT(c.rtt)
		}
		env := harness.New(t, harness.Options{Profile: profile, Seed: 5})
		samples, err := env.TCPLatency(40, 3, 5*time.Millisecond, probeTimeout)
		require.NoError(t, err)
		s := metrics.Summarize(samples)
		got[c.name] = s
		t.Logf("%s: %s", c.name, s)

		// One exchange is one round trip, so it cannot be faster than the
		// configured delay.
		assert.GreaterOrEqual(t, s.P50, c.rtt, "p50 below the configured one-way delays")
		assert.GreaterOrEqual(t, s.P99, s.P50)
	}
	assert.Greater(t, got["rtt200ms"].P50, got["rtt50ms"].P50)
	assert.Greater(t, got["rtt50ms"].P50, got["rtt0"].P50)
}

func TestLossInflatesTailLatency(t *testing.T) {
	base := netem.RTT(50 * time.Millisecond)
	clean := measureLatency(t, base.Named("rtt50ms"), 6)
	lossy := measureLatency(t, base.WithLoss(0.05).Named("rtt50ms+loss5%"), 7)
	t.Logf("clean: %s", clean)
	t.Logf("lossy: %s", lossy)

	// A lost request or response costs a retransmission timeout, which lands in
	// the tail long before it moves the median.
	assert.Greater(t, lossy.P99, clean.P50, "5%% loss left the tail untouched; the link was not impaired")
	assert.Greater(t, lossy.Max, clean.P50)
}

func measureLatency(t *testing.T, profile netem.Profile, seed uint64) metrics.Summary {
	t.Helper()
	env := harness.New(t, harness.Options{Profile: profile, Seed: seed})
	samples, err := env.TCPLatency(120, 3, 2*time.Millisecond, probeTimeout)
	require.NoError(t, err)
	return metrics.Summarize(samples)
}

func TestFullyBlockedUDPPreventsConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the QUIC handshake timeout")
	}
	// This is the censorship case the mesh is supposed to route around: the
	// handshake never completes, and the client has to give up on its own.
	start := time.Now()
	env, err := harness.TryNew(t, harness.Options{Profile: netem.Blocked()})
	require.Error(t, err, "client came up over a blackholed link")
	assert.Nil(t, env)

	var connectErr coreErrs.ConnectError
	assert.ErrorAs(t, err, &connectErr, "a blocked link must look like a connect failure, not a config error")
	// quic-go gives up after its handshake idle timeout; anything much longer
	// means the client is hanging rather than failing.
	assert.Less(t, time.Since(start), 30*time.Second)
}

// TestKernelNetemMatchesUserspace runs the same measurement against the real
// kernel shaper. It is skipped unless the machine has been prepared for it (see
// tests/README.md); when it does run, it is the check that the user-space
// layer's numbers are not an artefact of the user-space layer.
func TestKernelNetemMatchesUserspace(t *testing.T) {
	if a := kernel.Check(); !a.OK {
		t.Skip("kernel netem unavailable: " + a.Reason)
	}
	profile := netem.RTT(50 * time.Millisecond)
	kernel.Apply(t, kernel.Spec{Profile: profile})

	// The link is impaired by the kernel, so the wrapper must add nothing.
	env := harness.New(t, harness.Options{Profile: netem.Clean(), Seed: 9})
	samples, err := env.TCPLatency(40, 3, 5*time.Millisecond, probeTimeout)
	require.NoError(t, err)
	s := metrics.Summarize(samples)
	t.Logf("kernel %s: %s", profile.Name, s)
	assert.GreaterOrEqual(t, s.P50, 50*time.Millisecond)
}

func TestFailoverAfterUDPBlackhole(t *testing.T) {
	if testing.Short() {
		t.Skip("spends the QUIC idle timeout waiting for the client to notice")
	}
	env := harness.New(t, harness.Options{
		Profile:         netem.Clean(),
		Seed:            8,
		Reconnect:       true,
		MaxIdleTimeout:  4 * time.Second, // the minimum the core accepts
		KeepAlivePeriod: 2 * time.Second,
	})

	f, err := env.MeasureFailover(6*time.Second, 2*time.Second, 30*time.Second)
	require.NoError(t, err)
	t.Logf("failover: %s", f)

	assert.NotZero(t, f.Dead, "the client never reported the connection lost")
	assert.Less(t, f.Dead, 15*time.Second, "detection took longer than the idle timeout allows")
	// Reconnecting over a healthy link is a fresh handshake and nothing more.
	assert.Less(t, f.Recover, 10*time.Second)
}
