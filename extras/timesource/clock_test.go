package timesource

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSystemClock models a system whose wall clock and monotonic clock can be
// moved independently, which is exactly what an external clock step looks like.
type fakeSystemClock struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

// tick advances both clocks, as ordinary passage of time does.
func (f *fakeSystemClock) tick(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = f.wall.Add(d)
	f.mono += d
}

// step moves the wall clock only, as an outside agent setting the system time
// does.
func (f *fakeSystemClock) step(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = f.wall.Add(d)
}

func (f *fakeSystemClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wall
}

func (f *fakeSystemClock) since() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mono
}

func newTestClock(wall time.Time) (*Clock, *fakeSystemClock) {
	sys := &fakeSystemClock{wall: wall}
	return &Clock{wallNow: sys.now, mono: sys.since}, sys
}

func TestClockUncorrectedReadsSystemTime(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	clk, sys := newTestClock(epoch)

	assert.Equal(t, epoch, clk.Now())
	assert.False(t, clk.Corrected())
	assert.Zero(t, clk.Offset())

	sys.tick(time.Minute)
	assert.Equal(t, epoch.Add(time.Minute), clk.Now())
}

func TestClockAppliesCorrection(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	clk, sys := newTestClock(epoch)

	clk.Correct(trueTime.Sub(clk.Now()))
	require.True(t, clk.Corrected())
	assert.Equal(t, trueTime, clk.Now())

	sys.tick(90 * time.Second)
	assert.Equal(t, trueTime.Add(90*time.Second), clk.Now())
}

func TestClockKeepsCorrectionWhileTimePassesNormally(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	clk, sys := newTestClock(epoch)
	clk.Correct(trueTime.Sub(clk.Now()))

	for i := 0; i < 100; i++ {
		sys.tick(time.Hour)
		require.True(t, clk.Corrected())
	}
	assert.Equal(t, trueTime.Add(100*time.Hour), clk.Now())
}

// Once the tunnel comes up, the device's own ntp client sets the system clock.
// Keeping our offset on top of that would put the host as far into the future
// as it was in the past.
func TestClockReleasesCorrectionOnExternalStep(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	clk, sys := newTestClock(epoch)
	clk.Correct(trueTime.Sub(clk.Now()))

	sys.tick(30 * time.Second)
	sys.step(trueTime.Sub(epoch)) // sysntpd fixes the system clock

	assert.WithinDuration(t, trueTime.Add(30*time.Second), clk.Now(), time.Second)
	assert.False(t, clk.Corrected())
	assert.Zero(t, clk.Offset())
}

func TestClockToleratesSmallDrift(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	clk, sys := newTestClock(epoch)
	clk.Correct(time.Hour)

	sys.tick(time.Hour)
	sys.step(clockStepThreshold - time.Second)
	assert.Equal(t, sys.now().Add(time.Hour), clk.Now())
	assert.True(t, clk.Corrected())

	sys.step(2 * time.Second)
	assert.Equal(t, sys.now(), clk.Now())
	assert.False(t, clk.Corrected())
}

func TestClockNowIsConcurrencySafe(t *testing.T) {
	clk, sys := newTestClock(time.Unix(0, 0).UTC())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = clk.Now()
				_ = clk.Offset()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 500; j++ {
			clk.Correct(time.Duration(j) * time.Second)
			sys.tick(time.Millisecond)
		}
	}()
	wg.Wait()
}

// NewClock must behave like time.Now until something corrects it, since it is
// installed on every host, not just the broken ones.
func TestNewClockTracksTimeNow(t *testing.T) {
	clk := NewClock()
	assert.WithinDuration(t, time.Now(), clk.Now(), time.Second)
	assert.False(t, clk.Corrected())
}
