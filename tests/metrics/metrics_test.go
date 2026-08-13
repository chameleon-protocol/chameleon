package metrics

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ms(values ...int) []time.Duration {
	out := make([]time.Duration, len(values))
	for i, v := range values {
		out[i] = time.Duration(v) * time.Millisecond
	}
	return out
}

func TestPercentileOfEmptyAndSingleSample(t *testing.T) {
	assert.Zero(t, Percentile(nil, 0.5))
	assert.Equal(t, 7*time.Millisecond, Percentile(ms(7), 0.5))
	assert.Equal(t, 7*time.Millisecond, Percentile(ms(7), 0.99))
}

func TestPercentilePicksAnObservedSample(t *testing.T) {
	samples := ms(10, 20, 30, 40, 50, 60, 70, 80, 90, 100)
	// Nearest rank on ten samples: p50 is the fifth, p90 the ninth.
	assert.Equal(t, 50*time.Millisecond, Percentile(samples, 0.5))
	assert.Equal(t, 90*time.Millisecond, Percentile(samples, 0.9))
	assert.Equal(t, 100*time.Millisecond, Percentile(samples, 0.99))
	assert.Equal(t, 10*time.Millisecond, Percentile(samples, 0))
	assert.Equal(t, 100*time.Millisecond, Percentile(samples, 1))
}

func TestPercentileIgnoresInputOrderAndDoesNotMutate(t *testing.T) {
	samples := ms(90, 10, 50, 30, 70)
	original := slices.Clone(samples)
	assert.Equal(t, 50*time.Millisecond, Percentile(samples, 0.5))
	assert.Equal(t, original, samples, "callers keep their samples for other percentiles")
}

func TestPercentileTracksTheTail(t *testing.T) {
	// 98 fast samples and two slow ones. Nearest rank puts p99 of 100 samples
	// on the 99th, so the median stays fast while the p99 sees the tail.
	samples := make([]time.Duration, 98)
	for i := range samples {
		samples[i] = time.Millisecond
	}
	samples = append(samples, time.Second, time.Second)
	assert.Equal(t, time.Millisecond, Percentile(samples, 0.5))
	assert.Equal(t, time.Second, Percentile(samples, 0.99))

	// One slow sample in a hundred is above the p99 by definition: it only
	// shows up in the max. A test that asserts otherwise is asserting on noise.
	samples[98] = time.Millisecond
	assert.Equal(t, time.Millisecond, Percentile(samples, 0.99))
	assert.Equal(t, time.Second, Percentile(samples, 1))
}

func TestSummarize(t *testing.T) {
	s := Summarize(ms(30, 10, 20, 40))
	assert.Equal(t, 4, s.Count)
	assert.Equal(t, 10*time.Millisecond, s.Min)
	assert.Equal(t, 40*time.Millisecond, s.Max)
	assert.Equal(t, 20*time.Millisecond, s.P50)
	assert.Equal(t, 25*time.Millisecond, s.Mean)
	assert.NotEmpty(t, s.String())

	empty := Summarize(nil)
	assert.Zero(t, empty.Count)
	assert.Equal(t, "no samples", empty.String())
}

func TestThroughput(t *testing.T) {
	assert.Equal(t, 1024.0, Throughput(512, 500*time.Millisecond))
	assert.Zero(t, Throughput(1024, 0), "a zero interval means the test measured nothing")
	assert.Zero(t, Throughput(1024, -time.Second))
}

func TestRegression(t *testing.T) {
	assert.InDelta(t, 0.25, Regression(100, 75), 1e-9)
	assert.InDelta(t, -0.5, Regression(100, 150), 1e-9, "getting faster is a negative regression")
	assert.Zero(t, Regression(0, 100), "no baseline means no claim")
}

func TestFormatRate(t *testing.T) {
	assert.Equal(t, "2.00 MB/s", FormatRate(2<<20))
	assert.Equal(t, "4.00 KB/s", FormatRate(4<<10))
	assert.Equal(t, "12 B/s", FormatRate(12))
}
