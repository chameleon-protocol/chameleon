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
// These are not tests and are deliberately not named as such. They print
// tables, and the tables are the deliverable: they are what a repair gets
// compared against. Nothing here guards anything -- the only failure any of
// them can report is the harness failing to complete a transfer, which is a
// statement about the bed and not about the controller. The properties the
// congestion-control repairs are accountable for are asserted in
// brutal_test.go, brutal_repair_test.go and the brutal package's own tests; if
// you are looking for coverage, it is there and not here.
//
// They are benchmarks because that is the only shape the go tool offers for
// "runnable, but not part of the verdict": `go test` will not run them, so the
// four minutes they take cannot masquerade as a passing suite -- which is what
// they did as Test functions, and is most of why this package took six. The
// ns/op figure they report is meaningless: one iteration is a whole campaign,
// not an operation. Run them with
//
//	go test ./e2e/ -run '^$' -bench Baseline -benchtime 1x -v
//
// -benchtime 1x because each body is one full campaign. At the default one
// second the tool would settle on a single iteration anyway, since the first
// one takes far longer than that, but saying so is cheaper than relying on it.
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
func runBaseline(b *testing.B, profile netem.Profile, bw harness.Bandwidth, size int, idle time.Duration) wireReport {
	b.Helper()
	env := harness.New(b, harness.Options{
		Profile:        profile,
		Seed:           baselineSeed,
		Bandwidth:      bw,
		MaxIdleTimeout: idle,
	})
	// Released here rather than at the end of the benchmark: these sweeps build
	// one environment per cell per iteration, and TB cleanup would hold every
	// one of them open until the whole benchmark finished.
	defer env.Close()

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
	require.NoError(b, err)

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

// BenchmarkBaselineLossCompensation is scenario 1: does Brutal put more bytes
// on the wire as loss climbs, and does the extra buy anything?
//
// The profile carries 50ms of RTT on purpose. A pure-loss profile on loopback
// puts SRTT under a millisecond, which collapses the congestion window to a
// single datagram and measures that defect instead of this one.
//
// The 20% cell of this sweep is the one that turned out to be assertable, and
// it has been promoted out of here into TestBrutalCompensationOutsendsItsAbsence
// with a bound measured over repeated runs. What is left is the shape of the
// curve between 0 and 20%, which is a picture and not a threshold: the effect
// at 1% and 5% is smaller than this bed's run-to-run spread, so no row below
// the ackRate floor can carry an assertion without a measurement campaign per
// row.
func BenchmarkBaselineLossCompensation(b *testing.B) {
	const size = longTransfer
	// 20% is past the point where ackRate hits its 0.8 floor, which is the only
	// place the "sends 25% more" ceiling is actually reached.
	losses := []float64{0, 0.01, 0.05, 0.10, 0.20}

	type cell struct {
		loss float64
		comp bool
		r    wireReport
	}
	for range b.N {
		var cells []cell
		for _, loss := range losses {
			for _, comp := range []bool{true, false} {
				profile := netem.RTT(50 * time.Millisecond).WithLoss(loss).
					Named(fmt.Sprintf("rtt50ms+loss%.3g%%", loss*100))
				r := runBaseline(b, profile, harness.Bandwidth{
					BytesPerSec:             baselineDeclared,
					DisableLossCompensation: !comp,
				}, size, 0)
				cells = append(cells, cell{loss, comp, r})
			}
		}

		b.Logf("declared %s, %d byte echo, seed %d", metrics.FormatRate(baselineDeclared), size, baselineSeed)
		b.Logf("%-8s %-6s %-12s %-8s %-10s %-14s %-12s %-10s %-10s %-10s",
			"loss", "comp", "goodput", "vs decl", "elapsed", "wire bytes", "wire rate", "up drop", "p50", "p99")
		for _, c := range cells {
			b.Logf("%-8s %-6v %-12s %-8.3f %-10v %-14d %-12s %-10.2f %-10v %-10v",
				fmt.Sprintf("%.3g%%", c.loss*100), c.comp,
				metrics.FormatRate(c.r.Goodput), c.r.Goodput/baselineDeclared,
				c.r.Elapsed.Round(10*time.Millisecond),
				c.r.wireBytes(), metrics.FormatRate(c.r.wireRate()),
				c.r.UpDrop*100, c.r.LatencyP5.Round(time.Millisecond), c.r.LatencyP9.Round(time.Millisecond))
		}

		// The paired comparison the scenario is about: at the same loss and the
		// same seed, what did the divisor add and what did it buy?
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
			b.Logf("loss %.3g%%: compensation put x%.3f bytes on the wire, at x%.3f the rate, for x%.3f the goodput",
				loss*100,
				float64(on.wireBytes())/float64(off.wireBytes()),
				on.wireRate()/off.wireRate(),
				on.Goodput/off.Goodput)
		}
	}
}

// BenchmarkBaselineStandingQueue is scenario 2: on a link with a finite rate
// and a finite buffer, does the round trip climb as the transfer runs?
//
// cwnd is not observable from here -- it is internal to the core, and the tests
// module cannot import it. What is observable is the queue it permits: a window
// that is a linear function of SRTT never stops the sender from adding to a
// queue, so the standing queue grows until the buffer tail-drops. The series
// below is that state, sampled over the life of the transfer.
//
// The bound this produced is asserted, at the 2x declaration, by the p99 check
// in TestBrutalOverDeclarationCost. What stays here is the time series, which
// no single percentile can express and which is the reason a bound was
// believable in the first place.
//
// The probe stops when the transfer does. Samples taken after it would be
// measuring an idle link, and averaging those in would understate the queue by
// however long the probe outlived the load.
func BenchmarkBaselineStandingQueue(b *testing.B) {
	const linkRate = 1 << 20
	const baseRTT = 50 * time.Millisecond
	profile := netem.RateLimited(linkRate).WithRTT(baseRTT).Named("rate1MB/s+rtt50ms")

	for range b.N {
		for _, declared := range []uint64{linkRate, 2 * linkRate, 8 * linkRate} {
			env := harness.New(b, harness.Options{
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
			require.NoError(b, err)

			st := env.Ctrl.Stats()
			b.Logf("declared %s over a %s link, %v transfer: goodput %s, up offered %dB carried %dB drop %.2f%%",
				metrics.FormatRate(float64(declared)), metrics.FormatRate(linkRate),
				elapsed.Round(100*time.Millisecond),
				metrics.FormatRate(bps), st.Up.InBytes, st.Up.OutBytes, st.Up.LossRate()*100)

			// A per-second digest rather than every sample: the shape is the
			// claim, and a hundred lines per cell buries it. The queue delay is
			// the round trip minus the link's own 50ms, which is the part the
			// controller is responsible for.
			b.Logf("%-8s %-12s %-12s %-12s %-4s", "t", "min rtt", "max rtt", "min queue", "n")
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
				b.Logf("%-8v %-12v %-12v %-12v %-4d", cur,
					lo.Round(time.Millisecond), hi.Round(time.Millisecond),
					(lo - baseRTT).Round(time.Millisecond), n)
			}
			for _, s := range series {
				bk := s.At.Truncate(bucket)
				if bk != cur || n == 0 {
					flush()
					cur, lo, hi, n = bk, s.RTT, s.RTT, 0
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
			b.Logf("round trip during the transfer: %s", metrics.Summarize(all))
			// A standing queue is a floor, not a spike: the interesting statistic
			// is how rarely the link was ever seen empty.
			var bloated int
			for _, d := range all {
				if d > 2*baseRTT {
					bloated++
				}
			}
			if len(all) > 0 {
				b.Logf("%d/%d exchanges (%.0f%%) saw more than 2x the link's own round trip",
					bloated, len(all), float64(bloated)/float64(len(all))*100)
			}
		}
	}
}

// BenchmarkBaselineInteractiveFlow is scenario 3: what an interactive flow sees
// when it is the only thing on the link.
//
// 100 bytes every 50ms is roughly a shell session. The point of measuring it is
// where that lands relative to Brutal's sample floor, which is 50 packets over
// a 5 second window -- 10 packets a second. It lands right on it: the exchanges
// per second column reads 8.6 to 9.2 here, not the 20 the gap alone would
// suggest, because the probe is closed-loop and its cadence is the gap plus the
// round trip. So an interactive flow of this shape is at or just under the
// floor, and its send rate is decided by the pacer and the window alone.
//
// There is no assertion here and none is available. The controller's own
// verdict -- whether it is compensating -- is not observable from this module:
// the brutal package is internal to the core, and its Stats is run-loop only.
// The arithmetic half of the question is asserted where it can be, by
// TestBaselineMinSampleCount in that package. What is left here is the achieved
// exchange rate, which is the only end-to-end evidence about the floor there
// is, and round trips on an otherwise idle link, which mostly measure the
// profile's own delay -- and that is asserted by
// TestLatencyPercentilesTrackConfiguredRTT, though on BBR, since that one
// declares no bandwidth.
func BenchmarkBaselineInteractiveFlow(b *testing.B) {
	const count = 200
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
	// reported per row for exactly that reason, and it is the only end-to-end
	// evidence available about the floor: ackRate itself is decided inside the
	// controller, which this module cannot see.
	for range b.N {
		b.Logf("100 byte exchanges, 50ms between them, declared %s",
			metrics.FormatRate(baselineDeclared))
		b.Logf("%-18s %-10s %-10s %-10s %-10s %-10s %-12s",
			"profile", "p50", "p95", "p99", "max", "one-way p50", "exchanges/s")
		for _, c := range cases {
			env := harness.New(b, harness.Options{
				Profile:   c.profile,
				Seed:      baselineSeed,
				Bandwidth: harness.Bandwidth{BytesPerSec: baselineDeclared},
			})
			series, err := env.LatencySeries(harness.Probe{
				Count: count, Warmup: 3, Gap: 50 * time.Millisecond,
				Payload: 100, Timeout: 20 * time.Second,
			})
			require.NoError(b, err)
			samples := make([]time.Duration, len(series))
			for i, s := range series {
				samples[i] = s.RTT
			}
			sum := metrics.Summarize(samples)
			// The one-way figure is the round trip halved. Under a symmetric
			// profile that is the right expectation, but it is arithmetic, not a
			// measurement: nothing here can time a datagram in one direction only.
			var perSec float64
			if n := len(series); n > 1 && series[n-1].At > 0 {
				perSec = float64(n-1) / series[n-1].At.Seconds()
			}
			b.Logf("%-18s %-10v %-10v %-10v %-10v %-10v %-12.1f", c.profile.Name,
				sum.P50.Round(time.Millisecond),
				metrics.Percentile(samples, 0.95).Round(time.Millisecond),
				sum.P99.Round(time.Millisecond), sum.Max.Round(time.Millisecond),
				(sum.P50 / 2).Round(time.Millisecond), perSec)
		}
	}
}

// BenchmarkBaselineDeclaredVsAchieved is scenario 5: how much of a declared
// rate actually arrives, on a link with capacity to spare, as the path gets
// longer.
//
// The BDP at 20 Mbps and 200ms is 500KB, well inside the core's 8MB stream and
// 20MB connection windows, so a shortfall at 200ms is the controller's and not
// flow control's.
//
// The 200ms row of this table turned out to be the one cell here worth
// asserting, and it has been promoted into TestBrutalDeliversItsRateOnALongPath.
// The rest of the curve stays a picture: the rtt0 row's achieved fraction is
// decided by how much of a sub-second transfer is spent before the first round
// trip sample lands, which is a property of the transfer size and not of the
// controller, and pinning it would be pinning the bed.
func BenchmarkBaselineDeclaredVsAchieved(b *testing.B) {
	const size = longTransfer
	const declared = 20e6 / 8 // 20 Mbps expressed the way the config wants it

	for range b.N {
		b.Logf("declared %s (20 Mbps), no loss, %d byte echo", metrics.FormatRate(declared), size)
		b.Logf("%-12s %-14s %-12s %-14s %-10s %-10s",
			"rtt", "goodput", "vs declared", "wire bytes", "p50", "p99")
		for _, rtt := range []time.Duration{0, 50 * time.Millisecond, 200 * time.Millisecond} {
			profile := netem.Clean().Named("rtt0")
			if rtt > 0 {
				profile = netem.RTT(rtt)
			}
			r := runBaseline(b, profile, harness.Bandwidth{BytesPerSec: declared}, size, 0)
			b.Logf("%-12v %-14s %-12.3f %-14d %-10v %-10v", rtt,
				metrics.FormatRate(r.Goodput), r.Goodput/declared, r.wireBytes(),
				r.LatencyP5.Round(time.Millisecond), r.LatencyP9.Round(time.Millisecond))
		}
	}
}

// BenchmarkBaselineSharedBottleneck is scenario 4: two flows, one bottleneck,
// and the question of what a rate-declaring sender takes from its neighbour.
//
// The bed could not ask this before: netem's token bucket lives in the pipe,
// which is per-Conn, so two flows each got their own shaper and their own
// buffer and by construction could not interfere. netem.Bottleneck is the
// missing piece -- one bucket and one buffer that both flows reserve from.
//
// The neighbour is a second chameleon client that declares no bandwidth, which
// puts it on BBR. A real TCP competitor is not possible here and will not be:
// the impairment layer wraps a net.PacketConn, and TCP does not go through one.
//
// This one stays a measurement and is the clearest case for it. What share two
// controllers take of a shared link is a property of the pair, the buffer
// depth, the seed and the run length, and there is no number here that could be
// asserted without first deciding what share Brutal is entitled to -- which is
// a policy question this project has not answered, and answering it by writing
// down whatever today's run produced would be the exact defect these files were
// audited for.
func BenchmarkBaselineSharedBottleneck(b *testing.B) {
	const linkRate = 1 << 20 // 1 MB/s shared
	const runFor = 12 * time.Second

	for range b.N {
		// Zero declares nothing, which puts the first flow on BBR too. That cell
		// is the control: whatever share two identical controllers get is the
		// share the bed itself hands out, and a Brutal number only means
		// something as a departure from it.
		for _, declared := range []uint64{0, linkRate, 2 * linkRate, 8 * linkRate} {
			// One bottleneck per direction: an access link's uplink and downlink
			// do not take capacity from each other.
			up := netem.NewBottleneck(linkRate, 100*time.Millisecond)
			down := netem.NewBottleneck(linkRate, 100*time.Millisecond)
			shared := func(name string) netem.Profile {
				return netem.RTT(50*time.Millisecond).WithSharedBottleneck(up, down).Named(name)
			}

			env := harness.New(b, harness.Options{
				Profile:   shared("brutal-flow"),
				Seed:      baselineSeed,
				Bandwidth: harness.Bandwidth{BytesPerSec: declared},
			})
			// Bandwidth zero on the second client means the negotiated rate is
			// zero, which is what puts it on the configured controller (BBR).
			peer, err := env.AddClient(shared("bbr-flow"), baselineSeed+1, harness.Options{})
			require.NoError(b, err)

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
			require.NoError(b, brutalErr)
			require.NoError(b, bbrErr)

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
			b.Logf("flow 1 declared %s on a %s shared link, %v run",
				metrics.FormatRate(float64(declared)), metrics.FormatRate(linkRate), runFor)
			b.Logf("  %s: %d B back (%s), offered up %dB, dropped %.2f%%",
				first, brutalBytes, metrics.FormatRate(float64(brutalBytes)/runFor.Seconds()),
				bs.Up.InBytes, bs.Up.LossRate()*100)
			b.Logf("  bbr:    %d B back (%s), offered up %dB, dropped %.2f%%",
				bbrBytes, metrics.FormatRate(float64(bbrBytes)/runFor.Seconds()),
				ps.Up.InBytes, ps.Up.LossRate()*100)
			b.Logf("  flow 1 share %.1f%%, bottleneck up %s, down %s",
				share*100, up.Stats(), down.Stats())
		}
	}
}
