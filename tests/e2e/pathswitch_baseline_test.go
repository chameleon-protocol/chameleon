package e2e

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/chameleon-protocol/chameleon/core/v2/client"
	"github.com/chameleon-protocol/chameleon/core/v2/pathstats"
	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// What a candidate switch does to the congestion window, measured rather than
// reasoned about.
//
// These are not tests and are deliberately not named as such -- see the header
// of brutal_baseline_test.go for why the shape is a benchmark. They print the
// round trips the window is sized from, at 10ms resolution across the switch,
// and the tables are the deliverable. What is asserted about a switch is in
// pathswitch_test.go. Run them with
//
//	go test ./e2e/ -run '^$' -bench PathSwitch -benchtime 1x -v
//
// What they were used to settle:
//
//   - The window recovers in one round trip of the new path, not in the 500ms
//     Brutal's own rebaselining would take. ResetPathState clears the RTT
//     estimate's hasMeasurement flag, so the very first sample taken on the new
//     path replaces the minimum outright rather than being minimised against
//     the old one. Measured at 2 MB/s declared: 200ms -> 5ms recovers in under
//     10ms, 5ms -> 200ms in 228ms, both with no loss at all.
//
//   - Arming Brutal's OnPathChange on the replacement controller changes none
//     of those numbers. Its rebaselining holds the estimate on the previous
//     path's minimum while it measures the new one, and after ResetPathState
//     there is no previous minimum left to hold: what it falls back to during
//     its window is the same freshly reset figure it is trying to protect
//     against. It is not wired up for that reason.
//
//   - The one case that does not recover is a candidate with a standing queue
//     somebody else is keeping full. The first sample on the new path is the
//     queue, the minimum is a minimum so it never rises again, and the window
//     stays sized from it: measured at 487ms against a path whose own delay is
//     20ms, a window of 2.6 MB where 84 kB is right, still there after six
//     seconds. Nothing in the congestion controller can fix that -- a smaller
//     sample never arrives -- so it is a candidate a selector should decline,
//     not a switch a controller can repair.

// switchWindow is Brutal's GetCongestionWindow recomputed from the round trips
// the connection reports. The controller's own Stats are readable from the run
// loop only; its inputs are readable from anywhere.
func switchWindow(bps uint64, s pathstats.Stats) float64 {
	rtt := s.SmoothedRTT
	if s.MinRTT > 0 {
		rtt = min(max(rtt, s.MinRTT), 2*s.MinRTT)
	}
	rtt = max(rtt, time.Millisecond)
	cwnd := float64(bps) * rtt.Seconds() * 2
	return max(cwnd, 32*1252)
}

// switchLoad runs a bulk transfer through the tunnel until stop is called.
func switchLoad(b *testing.B, c client.Client, echo string) (stop func()) {
	b.Helper()
	conn, err := c.TCP(echo)
	if err != nil {
		b.Fatalf("open tunnel: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
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
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	var once atomic.Bool
	return func() {
		if once.CompareAndSwap(false, true) {
			close(done)
			_ = conn.Close()
		}
	}
}

// traceSwitch switches onto leg 1 under load and prints the window's inputs
// across the switch, finely for the first second and then every 100ms.
func traceSwitch(b *testing.B, name string, declared uint64, leg0, leg1 netem.Profile) {
	env := harness.New(b, harness.Options{
		Seed: 7, Candidates: 2, Profile: leg0,
		MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 2 * time.Second,
		Bandwidth: harness.Bandwidth{BytesPerSec: declared},
	})
	defer env.Close()
	legs := env.Paths.Legs
	env.Ctrl.SetFor(legs[0].Key(), leg0)
	env.Ctrl.SetFor(legs[1].Key(), leg1)

	stop := switchLoad(b, env.Client, env.TCPEcho)
	defer stop()
	stats := env.Client.(client.PathStatsProvider)
	time.Sleep(2 * time.Second) // settle on leg 0

	before, _ := stats.PathStats()
	b.Logf("=== %s: %s -> %s, declared %d B/s", name, leg0, leg1, declared)
	b.Logf("    before: min=%v srtt=%v window=%.0fB", before.MinRTT, before.SmoothedRTT, switchWindow(declared, before))

	start := time.Now()
	if err := env.Client.(client.PathController).SwitchTo(legs[1].Addr()); err != nil {
		b.Fatalf("switch: %v", err)
	}
	b.Logf("    SwitchTo blocked for %v", time.Since(start))

	var lastMin, lastSRTT time.Duration
	for at := time.Since(start); at < 3*time.Second; at = time.Since(start) {
		s, _ := stats.PathStats()
		if s.MinRTT != lastMin || s.SmoothedRTT != lastSRTT || at > time.Second {
			b.Logf("    t=+%6.0fms  min=%-14v srtt=%-14v window=%9.0fB lost=%d",
				float64(at.Microseconds())/1000, s.MinRTT, s.SmoothedRTT, switchWindow(declared, s), s.PacketsLost)
			lastMin, lastSRTT = s.MinRTT, s.SmoothedRTT
		}
		if at < time.Second {
			time.Sleep(10 * time.Millisecond)
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	after, _ := stats.PathStats()
	b.Logf("    after 3s: min=%v srtt=%v window=%.0fB, %d packets lost of %d sent across the switch",
		after.MinRTT, after.SmoothedRTT, switchWindow(declared, after),
		after.PacketsLost-before.PacketsLost, after.PacketsSent-before.PacketsSent)
}

const switchDeclared = 2 << 20

// BenchmarkPathSwitchLongToShort is the direction the reset is least needed in:
// a minimum can fall on its own, so even without a reset the estimate follows.
func BenchmarkPathSwitchLongToShort(b *testing.B) {
	for range b.N {
		traceSwitch(b, "long->short", switchDeclared,
			netem.RTT(200*time.Millisecond), netem.RTT(5*time.Millisecond))
	}
}

// BenchmarkPathSwitchShortToLong is the direction that needs it: a lifetime
// minimum cannot rise, so without the reset the window stays sized for the
// candidate the connection left.
func BenchmarkPathSwitchShortToLong(b *testing.B) {
	for range b.N {
		traceSwitch(b, "short->long", switchDeclared,
			netem.RTT(5*time.Millisecond), netem.RTT(200*time.Millisecond))
	}
}

// BenchmarkPathSwitchOverDeclared switches onto a candidate carrying half the
// declared rate. The pacer offers the declared rate whatever the window says,
// so here the window is what sets the depth of the standing queue: measured,
// the queue settles at exactly cwnd divided by the link's rate.
func BenchmarkPathSwitchOverDeclared(b *testing.B) {
	for range b.N {
		traceSwitch(b, "over-declared", switchDeclared,
			netem.RTT(20*time.Millisecond),
			netem.RTT(20*time.Millisecond).WithRate(1<<20).Named("rtt20ms+1MB/s"))
	}
}

// BenchmarkPathSwitchIntoForeignQueue is the case that does not recover, and
// the reason this file exists.
//
// The neighbour reaches the server past the legs, at Paths.Origin(): a leg
// carries one client, because it learns where to send the server's replies from
// the last datagram it forwarded. What the two flows share is the buffer, which
// is what the experiment is about.
func BenchmarkPathSwitchIntoForeignQueue(b *testing.B) {
	for range b.N {
		benchForeignQueue(b)
	}
}

func benchForeignQueue(b *testing.B) {
	bn := netem.NewBottleneck(1<<20, 300*time.Millisecond)
	shared := netem.Profile{
		Name: "shared 1MB/s buffer",
		Up:   netem.Link{Delay: 10 * time.Millisecond, Shared: bn},
		Down: netem.Link{Delay: 10 * time.Millisecond, Shared: bn},
	}
	clean := netem.RTT(20 * time.Millisecond)

	env := harness.New(b, harness.Options{
		Seed: 11, Candidates: 2, Profile: clean,
		MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 2 * time.Second,
		Bandwidth: harness.Bandwidth{BytesPerSec: switchDeclared},
	})
	defer env.Close()
	legs := env.Paths.Legs
	env.Ctrl.SetFor(legs[0].Key(), clean)
	env.Ctrl.SetFor(legs[1].Key(), shared)

	// Our own tunnel first. Opening it after the neighbour has started has been
	// seen to take longer than the idle timeout, which kills the connection this
	// measurement is about before it begins.
	stop := switchLoad(b, env.Client, env.TCPEcho)
	defer stop()

	peer, err := env.AddClientAt(env.Paths.Origin(), shared, 12, harness.Options{
		MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 2 * time.Second,
		Bandwidth: harness.Bandwidth{BytesPerSec: switchDeclared},
	})
	if err != nil {
		b.Fatalf("neighbour: %v", err)
	}
	pstop := switchLoad(b, peer.Client, env.TCPEcho)
	defer pstop()

	time.Sleep(3 * time.Second) // let the neighbour fill the buffer
	stats := env.Client.(client.PathStatsProvider)
	before, _ := stats.PathStats()
	b.Logf("=== into a foreign queue: leg 0 clean, leg 1 behind a buffer the neighbour keeps full")
	b.Logf("    before: min=%v srtt=%v window=%.0fB", before.MinRTT, before.SmoothedRTT, switchWindow(switchDeclared, before))

	start := time.Now()
	if err := env.Client.(client.PathController).SwitchTo(legs[1].Addr()); err != nil {
		b.Fatalf("switch: %v", err)
	}
	for at := time.Since(start); at < 6*time.Second; at = time.Since(start) {
		s, _ := stats.PathStats()
		b.Logf("    t=+%6.0fms  min=%-14v srtt=%-14v window=%9.0fB lost=%d",
			float64(at.Microseconds())/1000, s.MinRTT, s.SmoothedRTT, switchWindow(switchDeclared, s), s.PacketsLost)
		time.Sleep(250 * time.Millisecond)
	}
}
