// Package metrics turns raw test measurements into the numbers acceptance
// criteria are written against: throughput, and latency percentiles.
package metrics

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// Percentile returns the p-th percentile of samples, p in [0, 1], by nearest
// rank. Nearest rank rather than interpolation because these samples are
// observed latencies: an interpolated p99 is a number nothing ever measured,
// and at the sample counts a test can afford it is mostly noise anyway.
//
// Percentile returns zero for an empty sample set.
func Percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	rank := int(math.Ceil(float64(len(sorted)) * p))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// Summary is the shape of a latency sample set.
type Summary struct {
	Count int
	Min   time.Duration
	P50   time.Duration
	P90   time.Duration
	P99   time.Duration
	Max   time.Duration
	Mean  time.Duration
}

// Summarize computes every percentile at once. The zero Summary describes an
// empty sample set.
func Summarize(samples []time.Duration) Summary {
	if len(samples) == 0 {
		return Summary{}
	}
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	var total time.Duration
	for _, s := range sorted {
		total += s
	}
	return Summary{
		Count: len(sorted),
		Min:   sorted[0],
		P50:   Percentile(sorted, 0.5),
		P90:   Percentile(sorted, 0.9),
		P99:   Percentile(sorted, 0.99),
		Max:   sorted[len(sorted)-1],
		Mean:  total / time.Duration(len(sorted)),
	}
}

func (s Summary) String() string {
	if s.Count == 0 {
		return "no samples"
	}
	return fmt.Sprintf("n=%d min=%s p50=%s p90=%s p99=%s max=%s mean=%s",
		s.Count, round(s.Min), round(s.P50), round(s.P90), round(s.P99), round(s.Max), round(s.Mean))
}

func round(d time.Duration) time.Duration {
	if d < time.Millisecond {
		return d.Round(time.Microsecond)
	}
	return d.Round(100 * time.Microsecond)
}

// Throughput is bytes per second. It returns zero for a non-positive elapsed
// time so that a mis-instrumented test reads as "measured nothing" rather than
// as an infinitely fast link.
func Throughput(bytes int64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(bytes) / elapsed.Seconds()
}

// FormatRate renders a byte-per-second figure for test logs.
func FormatRate(bps float64) string {
	switch {
	case bps >= 1<<20:
		return fmt.Sprintf("%.2f MB/s", bps/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.2f KB/s", bps/(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}

// Regression is how much worse got is than baseline, as a fraction: 0.1 means
// got is 10% slower. Negative means it got faster. This is the number a
// "performance must not regress by more than X%" criterion compares.
func Regression(baseline, got float64) float64 {
	if baseline <= 0 {
		return 0
	}
	return (baseline - got) / baseline
}
