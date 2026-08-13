package e2e

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/tests/v2/harness"
	"github.com/chameleon-protocol/chameleon/tests/v2/metrics"
	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// Baseline measurements of Brutal as shipped, on a real client and a real
// server over the user-space impaired link.
//
// These are not assertions. They print tables, and the tables are the
// deliverable: they are what a repair gets compared against. Run them with
//
//	go test ./e2e/ -run Baseline -v -timeout 30m
//
// Nothing here is skipped under -short except by shrinking the transfers,
// because a truncated run of a congestion-control measurement is not a smaller
// measurement, it is a different one.
//
// What the numbers are and are not:
//
//   - Everything is loopback through netem.Conn, which is not a *net.UDPConn:
//     no GSO, no ECN, no batched syscalls. Absolute throughput is therefore an
//     artefact of the bed as much as of the transport.
//   - The comparisons are what carry: compensation on vs off at the same seed
//     and profile, declared rate vs achieved rate at the same profile, one flow
//     vs another over the same bottleneck. Those hold.
//   - Loss is independent per datagram, so recovery has an easier time here
//     than on a real path, which loses in bursts.

// baselineDeclared is the rate both ends declare in most of these runs. It is
// far below what loopback can carry, so the link is never the binding
// constraint and the controller is.
const baselineDeclared = 2 << 20 // 2 MB/s

// baselineSeed keeps the loss draws identical across the cells of a comparison,
// so that "compensation on moved more bytes" is not a statement about which
// datagrams the RNG happened to drop.
const baselineSeed = 11

// wireReport is what one run cost on the wire, taken from the link's own
// counters rather than from the transport's opinion of itself.
type wireReport struct {
	Goodput   float64 // payload bytes/s, one way
	UpIn      uint64  // bytes the client offered to the link
	UpOut     uint64  // bytes the link carried
	DownIn    uint64  // bytes the server sent, as seen arriving at the client
	DownOut   uint64
	UpDrop    float64
	Overflow  uint64
	Elapsed   time.Duration
	LatencyP5 time.Duration
	LatencyP9 time.Duration
}

// wireBytes is the total offered to the link in both directions. Both ends run
// Brutal and the load is an echo, so a single direction would report half the
// controller's decision.
func (r wireReport) wireBytes() uint64 { return r.UpIn + r.DownIn }

// wireRate is the bytes offered to the link per second.
//
// This, and not wireBytes, is what "sends more under loss" means. A fixed-size
// transfer moves a fixed amount of payload however fast it is sent, so its
// total wire volume only reflects retransmissions; the compensation shows up as
// the same bytes leaving sooner. The distinction stops being academic the
// moment the flow is backlogged rather than fixed-size, which is the case on a
// shared bottleneck.
func (r wireReport) wireRate() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.wireBytes()) / r.Elapsed.Seconds()
}

// runBaseline drives one bulk transfer with a latency probe alongside it, and
// reports both what got through and what it cost on the wire.
//
// The probe matters: on an idle link every controller looks the same, and the
// cost of a send rate only appears as queueing that someone else has to wait
// behind.
func runBaseline(t *testing.T, profile netem.Profile, bw harness.Bandwidth, size int, idle time.Duration) wireReport {
	t.Helper()
	env := harness.New(t, harness.Options{
		Profile:        profile,
		Seed:           baselineSeed,
		Bandwidth:      bw,
		MaxIdleTimeout: idle,
	})

	var wg sync.WaitGroup
	var lat []time.Duration
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(300 * time.Millisecond) // let the transfer reach steady state
		lat, _ = env.TCPLatency(40, 2, 20*time.Millisecond, 20*time.Second)
	}()

	start := time.Now()
	bps, err := env.TCPThroughput(size, 120*time.Second)
	elapsed := time.Since(start)
	wg.Wait()
	require.NoError(t, err)

	st := env.Ctrl.Stats()
	return wireReport{
		Goodput:   bps,
		UpIn:      st.Up.InBytes,
		UpOut:     st.Up.OutBytes,
		DownIn:    st.Down.InBytes,
		DownOut:   st.Down.OutBytes,
		UpDrop:    st.Up.LossRate(),
		Overflow:  st.Overflow,
		Elapsed:   elapsed,
		LatencyP5: metrics.Percentile(lat, 0.5),
		LatencyP9: metrics.Percentile(lat, 0.99),
	}
}

// TestBaselineLossCompensation is scenario 1: does Brutal put more bytes on the
// wire as loss climbs, and does the extra buy anything?
//
// The profile carries 50ms of RTT on purpose. A pure-loss profile on loopback
// puts SRTT under a millisecond, which collapses the congestion window to a
// single datagram and measures that defect instead of this one; the collapse
// gets its own cell below.
func TestBaselineLossCompensation(t *testing.T) {
	size := longTransfer
	if testing.Short() {
		size = shortTransfer
	}
	// 20% is past the point where ackRate hits its 0.8 floor, which is the only
	// place the "sends 25% more" ceiling is actually reached.
	losses := []float64{0, 0.01, 0.05, 0.10, 0.20}

	type cell struct {
		loss float64
		comp bool
		r    wireReport
	}
	var cells []cell
	for _, loss := range losses {
		for _, comp := range []bool{true, false} {
			profile := netem.RTT(50 * time.Millisecond).WithLoss(loss).
				Named(fmt.Sprintf("rtt50ms+loss%.3g%%", loss*100))
			name := fmt.Sprintf("loss%.3g%%/comp=%v", loss*100, comp)
			var r wireReport
			t.Run(name, func(t *testing.T) {
				r = runBaseline(t, profile, harness.Bandwidth{
					BytesPerSec:             baselineDeclared,
					DisableLossCompensation: !comp,
				}, size, 0)
			})
			cells = append(cells, cell{loss, comp, r})
		}
	}

	t.Logf("declared %s, %d byte echo, seed %d", metrics.FormatRate(baselineDeclared), size, baselineSeed)
	t.Logf("%-8s %-6s %-12s %-8s %-10s %-14s %-12s %-10s %-10s %-10s",
		"loss", "comp", "goodput", "vs decl", "elapsed", "wire bytes", "wire rate", "up drop", "p50", "p99")
	for _, c := range cells {
		t.Logf("%-8s %-6v %-12s %-8.3f %-10v %-14d %-12s %-10.2f %-10v %-10v",
			fmt.Sprintf("%.3g%%", c.loss*100), c.comp,
			metrics.FormatRate(c.r.Goodput), c.r.Goodput/baselineDeclared,
			c.r.Elapsed.Round(10*time.Millisecond),
			c.r.wireBytes(), metrics.FormatRate(c.r.wireRate()),
			c.r.UpDrop*100, c.r.LatencyP5.Round(time.Millisecond), c.r.LatencyP9.Round(time.Millisecond))
	}

	// The paired comparison the scenario is about: at the same loss and the same
	// seed, what did the divisor add and what did it buy?
	for _, loss := range losses {
		var on, off wireReport
		for _, c := range cells {
			if c.loss != loss {
				continue
			}
			if c.comp {
				on = c.r
			} else {
				off = c.r
			}
		}
		if off.wireBytes() == 0 {
			continue
		}
		t.Logf("loss %.3g%%: compensation put x%.3f bytes on the wire, at x%.3f the rate, for x%.3f the goodput",
			loss*100,
			float64(on.wireBytes())/float64(off.wireBytes()),
			on.wireRate()/off.wireRate(),
			on.Goodput/off.Goodput)
	}
}

// TestBaselineCwndFloorOnFastPaths is the mirror case the profile above avoids:
// the same loss with no added delay, where SRTT is a few hundred microseconds
// and cwnd = bps x SRTT x 2 is one or two datagrams.
//
// It runs with a short idle timeout because the expected outcome for the low
// declarations is that the connection stops making progress; without the bound
// each cell would sit for the default 30s.
func TestBaselineCwndFloorOnFastPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("cells here are expected to stall, and stalling takes the idle timeout")
	}
	profile := netem.Loss(0.05)
	t.Logf("%-14s %-14s %-12s %-10s", "declared", "goodput", "vs declared", "outcome")
	for _, declared := range []uint64{1 << 20, 2 << 20, 8 << 20, 64 << 20} {
		declared := declared
		t.Run(metrics.FormatRate(float64(declared)), func(t *testing.T) {
			env := harness.New(t, harness.Options{
				Profile:        profile,
				Seed:           baselineSeed,
				Bandwidth:      harness.Bandwidth{BytesPerSec: declared},
				MaxIdleTimeout: 4 * time.Second,
			})
			bps, err := env.TCPThroughput(2<<20, 25*time.Second)
			outcome := "completed"
			if err != nil {
				outcome = "stalled: " + err.Error()
				bps = 0
			}
			t.Logf("%-14s %-14s %-12.3f %-10s", metrics.FormatRate(float64(declared)),
				metrics.FormatRate(bps), bps/float64(declared), outcome)
		})
	}
}

// TestBaselineStandingQueue is scenario 2: on a link with a finite rate and a
// finite buffer, does the round trip climb as the transfer runs?
//
// cwnd is not observable from here -- it is internal to the core, and the tests
// module cannot import it. What is observable is the queue it permits: a window
// that is a linear function of SRTT never stops the sender from adding to a
// queue, so the standing queue grows until the buffer tail-drops. The series
// below is that state, sampled over the life of the transfer.
//
// The probe stops when the transfer does. Samples taken after it would be
// measuring an idle link, and averaging those in would understate the queue by
// however long the probe outlived the load.
func TestBaselineStandingQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a transfer long enough for a queue to build")
	}
	const linkRate = 1 << 20
	const baseRTT = 50 * time.Millisecond
	profile := netem.RateLimited(linkRate).WithRTT(baseRTT).Named("rate1MB/s+rtt50ms")

	for _, declared := range []uint64{linkRate, 2 * linkRate, 8 * linkRate} {
		declared := declared
		t.Run(metrics.FormatRate(float64(declared)), func(t *testing.T) {
			env := harness.New(t, harness.Options{
				Profile:   profile,
				Seed:      baselineSeed,
				Bandwidth: harness.Bandwidth{BytesPerSec: declared},
			})

			done := make(chan struct{})
			var wg sync.WaitGroup
			var series []harness.LatencySample
			wg.Add(1)
			go func() {
				defer wg.Done()
				series, _ = env.LatencySeries(harness.Probe{
					Count: 500, Warmup: 1, Gap: 100 * time.Millisecond,
					Timeout: 30 * time.Second, Stop: done,
				})
			}()
			start := time.Now()
			bps, err := env.TCPThroughput(12<<20, 180*time.Second)
			elapsed := time.Since(start)
			close(done)
			wg.Wait()
			require.NoError(t, err)

			st := env.Ctrl.Stats()
			t.Logf("declared %s over a %s link, %v transfer: goodput %s, up offered %dB carried %dB drop %.2f%%",
				metrics.FormatRate(float64(declared)), metrics.FormatRate(linkRate),
				elapsed.Round(100*time.Millisecond),
				metrics.FormatRate(bps), st.Up.InBytes, st.Up.OutBytes, st.Up.LossRate()*100)

			// A per-second digest rather than every sample: the shape is the
			// claim, and a hundred lines per cell buries it. The queue delay is
			// the round trip minus the link's own 50ms, which is the part the
			// controller is responsible for.
			t.Logf("%-8s %-12s %-12s %-12s %-4s", "t", "min rtt", "max rtt", "min queue", "n")
			const bucket = time.Second
			var (
				lo, hi time.Duration
				n      int
				cur    time.Duration
			)
			flush := func() {
				if n == 0 {
					return
				}
				t.Logf("%-8v %-12v %-12v %-12v %-4d", cur,
					lo.Round(time.Millisecond), hi.Round(time.Millisecond),
					(lo - baseRTT).Round(time.Millisecond), n)
			}
			for _, s := range series {
				b := s.At.Truncate(bucket)
				if b != cur || n == 0 {
					flush()
					cur, lo, hi, n = b, s.RTT, s.RTT, 0
				}
				lo = min(lo, s.RTT)
				hi = max(hi, s.RTT)
				n++
			}
			flush()

			all := make([]time.Duration, len(series))
			for i, s := range series {
				all[i] = s.RTT
			}
			t.Logf("round trip during the transfer: %s", metrics.Summarize(all))
			// A standing queue is a floor, not a spike: the interesting statistic
			// is how rarely the link was ever seen empty.
			var bloated int
			for _, d := range all {
				if d > 2*baseRTT {
					bloated++
				}
			}
			if len(all) > 0 {
				t.Logf("%d/%d exchanges (%.0f%%) saw more than 2x the link's own round trip",
					bloated, len(all), float64(bloated)/float64(len(all))*100)
			}
		})
	}
}

// TestBaselineInteractiveFlow is scenario 3: what an interactive flow sees when
// it is the only thing on the link.
//
// 100 bytes every 50ms is roughly a shell session. The point of measuring it is
// that this flow is below the rate at which Brutal's own feedback loop has
// anything to work with -- see TestBaselineMinSampleCount in the brutal package
// for where that floor is -- so its behaviour is decided by the pacer and the
// window alone.
func TestBaselineInteractiveFlow(t *testing.T) {
	count := 200
	if testing.Short() {
		count = 40
	}
	cases := []struct {
		name    string
		profile netem.Profile
	}{
		{"rtt50ms", netem.RTT(50 * time.Millisecond)},
		{"rtt50ms+loss1%", netem.RTT(50 * time.Millisecond).WithLoss(0.01).Named("rtt50ms+loss1%")},
		{"rtt50ms+loss5%", netem.RTT(50 * time.Millisecond).WithLoss(0.05).Named("rtt50ms+loss5%")},
	}
	// The probe is closed-loop -- it waits for the echo, then pauses -- so its
	// cadence is the gap plus the round trip, not the gap. That matters here
	// more than anywhere else: Brutal's sample floor is a packet rate, and the
	// difference between "every 50ms" and "every 50ms plus 52ms of path" is the
	// difference between clearing the floor and not. The achieved rate is
	// reported per row for exactly that reason.
	t.Logf("100 byte exchanges, 50ms between them, declared %s",
		metrics.FormatRate(baselineDeclared))
	t.Logf("%-18s %-10s %-10s %-10s %-10s %-10s %-12s",
		"profile", "p50", "p95", "p99", "max", "one-way p50", "exchanges/s")
	for _, c := range cases {
		env := harness.New(t, harness.Options{
			Profile:   c.profile,
			Seed:      baselineSeed,
			Bandwidth: harness.Bandwidth{BytesPerSec: baselineDeclared},
		})
		series, err := env.LatencySeries(harness.Probe{
			Count: count, Warmup: 3, Gap: 50 * time.Millisecond,
			Payload: 100, Timeout: 20 * time.Second,
		})
		require.NoError(t, err)
		samples := make([]time.Duration, len(series))
		for i, s := range series {
			samples[i] = s.RTT
		}
		sum := metrics.Summarize(samples)
		// The one-way figure is the round trip halved. Under a symmetric profile
		// that is the right expectation, but it is arithmetic, not a measurement:
		// nothing here can time a datagram in one direction only.
		var perSec float64
		if n := len(series); n > 1 && series[n-1].At > 0 {
			perSec = float64(n-1) / series[n-1].At.Seconds()
		}
		t.Logf("%-18s %-10v %-10v %-10v %-10v %-10v %-12.1f", c.profile.Name,
			sum.P50.Round(time.Millisecond),
			metrics.Percentile(samples, 0.95).Round(time.Millisecond),
			sum.P99.Round(time.Millisecond), sum.Max.Round(time.Millisecond),
			(sum.P50 / 2).Round(time.Millisecond), perSec)
	}
}

// TestBaselineInteractiveAckRate asks whether an interactive flow ever gets
// past Brutal's sample floor, end to end rather than in simulation.
//
// The controller has no test hook, so the only way to see ackRate from outside
// the core is its debug print. The lines go to stdout, not to the test log, so
// this test is only meaningful under -v: look for "ACK rate" versus "Not enough
// samples". A 100 byte exchange every 50ms is about 20 ack-eliciting packets a
// second each way, and the floor is 50 samples over a 5 second window.
func TestBaselineInteractiveAckRate(t *testing.T) {
	if testing.Short() {
		t.Skip("needs several debug print intervals to say anything")
	}
	t.Setenv("CHAMELEON_BRUTAL_DEBUG", "1")
	env := harness.New(t, harness.Options{
		Profile:   netem.RTT(50 * time.Millisecond).WithLoss(0.05).Named("rtt50ms+loss5%"),
		Seed:      baselineSeed,
		Bandwidth: harness.Bandwidth{BytesPerSec: baselineDeclared},
	})
	t.Log("stdout below carries the controller's own view of ackRate")
	_, err := env.LatencySeries(harness.Probe{
		Count: 300, Warmup: 3, Gap: 50 * time.Millisecond,
		Payload: 100, Timeout: 20 * time.Second,
	})
	require.NoError(t, err)
}

// TestBaselineDeclaredVsAchieved is scenario 5: how much of a declared rate
// actually arrives, on a link with capacity to spare, as the path gets longer.
func TestBaselineDeclaredVsAchieved(t *testing.T) {
	size := longTransfer
	if testing.Short() {
		size = shortTransfer
	}
	const declared = 20e6 / 8 // 20 Mbps expressed the way the config wants it

	t.Logf("declared %s (20 Mbps), no loss, %d byte echo", metrics.FormatRate(declared), size)
	t.Logf("%-12s %-14s %-12s %-14s %-10s %-10s",
		"rtt", "goodput", "vs declared", "wire bytes", "p50", "p99")
	for _, rtt := range []time.Duration{0, 50 * time.Millisecond, 200 * time.Millisecond} {
		profile := netem.Clean().Named("rtt0")
		if rtt > 0 {
			profile = netem.RTT(rtt)
		}
		r := runBaseline(t, profile, harness.Bandwidth{BytesPerSec: declared}, size, 0)
		t.Logf("%-12v %-14s %-12.3f %-14d %-10v %-10v", rtt,
			metrics.FormatRate(r.Goodput), r.Goodput/declared, r.wireBytes(),
			r.LatencyP5.Round(time.Millisecond), r.LatencyP9.Round(time.Millisecond))
	}
	// The BDP at 20 Mbps and 200ms is 500KB, well inside the core's 8MB stream
	// and 20MB connection windows, so a shortfall at 200ms is the controller's
	// and not flow control's.
}

// TestBaselineSharedBottleneck is scenario 4: two flows, one bottleneck, and
// the question of what a rate-declaring sender takes from its neighbour.
//
// The bed could not ask this before: netem's token bucket lives in the pipe,
// which is per-Conn, so two flows each got their own shaper and their own
// buffer and by construction could not interfere. netem.Bottleneck is the
// missing piece -- one bucket and one buffer that both flows reserve from.
//
// The neighbour is a second chameleon client that declares no bandwidth, which
// puts it on BBR. A real TCP competitor is not possible here and will not be:
// the impairment layer wraps a net.PacketConn, and TCP does not go through one.
func TestBaselineSharedBottleneck(t *testing.T) {
	if testing.Short() {
		t.Skip("two concurrent flows for several seconds each")
	}
	const linkRate = 1 << 20 // 1 MB/s shared
	const runFor = 12 * time.Second

	// Zero declares nothing, which puts the first flow on BBR too. That cell is
	// the control: whatever share two identical controllers get is the share the
	// bed itself hands out, and a Brutal number only means something as a
	// departure from it.
	for _, declared := range []uint64{0, linkRate, 2 * linkRate, 8 * linkRate} {
		declared := declared
		name := "brutal=" + metrics.FormatRate(float64(declared))
		if declared == 0 {
			name = "control-bbr-vs-bbr"
		}
		t.Run(name, func(t *testing.T) {
			// One bottleneck per direction: an access link's uplink and downlink
			// do not take capacity from each other.
			up := netem.NewBottleneck(linkRate, 100*time.Millisecond)
			down := netem.NewBottleneck(linkRate, 100*time.Millisecond)
			shared := func(name string) netem.Profile {
				return netem.RTT(50*time.Millisecond).WithSharedBottleneck(up, down).Named(name)
			}

			env := harness.New(t, harness.Options{
				Profile:   shared("brutal-flow"),
				Seed:      baselineSeed,
				Bandwidth: harness.Bandwidth{BytesPerSec: declared},
			})
			// Bandwidth zero on the second client means the negotiated rate is
			// zero, which is what puts it on the configured controller (BBR).
			peer, err := env.AddClient(shared("bbr-flow"), baselineSeed+1, harness.Options{})
			require.NoError(t, err)

			var wg sync.WaitGroup
			var brutalBytes, bbrBytes int64
			var brutalErr, bbrErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				brutalBytes, brutalErr = env.TCPLoadFor(env.Client, runFor)
			}()
			go func() {
				defer wg.Done()
				bbrBytes, bbrErr = env.TCPLoadFor(peer.Client, runFor)
			}()
			wg.Wait()
			require.NoError(t, brutalErr)
			require.NoError(t, bbrErr)

			bs, ps := env.Ctrl.Stats(), peer.Ctrl.Stats()
			total := brutalBytes + bbrBytes
			share := 0.0
			if total > 0 {
				share = float64(brutalBytes) / float64(total)
			}
			first := "brutal"
			if declared == 0 {
				first = "bbr #1"
			}
			t.Logf("flow 1 declared %s on a %s shared link, %v run",
				metrics.FormatRate(float64(declared)), metrics.FormatRate(linkRate), runFor)
			t.Logf("  %s: %d B back (%s), offered up %dB, dropped %.2f%%",
				first, brutalBytes, metrics.FormatRate(float64(brutalBytes)/runFor.Seconds()),
				bs.Up.InBytes, bs.Up.LossRate()*100)
			t.Logf("  bbr:    %d B back (%s), offered up %dB, dropped %.2f%%",
				bbrBytes, metrics.FormatRate(float64(bbrBytes)/runFor.Seconds()),
				ps.Up.InBytes, ps.Up.LossRate()*100)
			t.Logf("  flow 1 share %.1f%%, bottleneck up %s, down %s",
				share*100, up.Stats(), down.Stats())
		})
	}
}
