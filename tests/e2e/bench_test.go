package e2e

import (
	"testing"
	"time"

	"github.com/apernet/hysteria/tests/v2/harness"
	"github.com/apernet/hysteria/tests/v2/netem"
)

// These benchmarks are the regression baseline. Unlike a microbenchmark of one
// copy loop they exercise the whole path -- syscalls, QUIC, congestion control,
// the proxy protocol -- which is the only level at which "throughput regressed
// by X%" means anything.
//
// Run them as:
//
//	go test ./e2e/ -run '^$' -bench . -benchtime 5x
//
// -benchtime in iterations rather than seconds, because one iteration moves a
// fixed number of bytes and an impaired profile makes that slow on purpose.

const benchTransfer = 4 << 20

func BenchmarkTunnelThroughput(b *testing.B) {
	for _, profile := range netem.Standard() {
		b.Run(profile.Name, func(b *testing.B) {
			env := harness.New(b, harness.Options{Profile: profile, Seed: 100})
			b.SetBytes(benchTransfer)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := env.TCPThroughput(benchTransfer, 120*time.Second); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTunnelRoundTrip(b *testing.B) {
	for _, profile := range []netem.Profile{
		netem.Clean(),
		netem.Loss(0.01),
		netem.RTT(50 * time.Millisecond),
	} {
		b.Run(profile.Name, func(b *testing.B) {
			env := harness.New(b, harness.Options{Profile: profile, Seed: 101})
			// One warmup exchange per iteration would dominate; TCPLatency does
			// its own warmup and then reports b.N round trips on one stream.
			b.ResetTimer()
			if _, err := env.TCPLatency(b.N, 1, 0, probeTimeout); err != nil {
				b.Fatal(err)
			}
		})
	}
}
