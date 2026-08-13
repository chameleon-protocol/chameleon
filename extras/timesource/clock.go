package timesource

import (
	"sync"
	"time"
)

// clockStepThreshold is how far the system clock may move relative to the
// monotonic clock before Clock concludes it was stepped from the outside.
// It has to absorb the drift of a cheap oscillator over a long uptime without
// firing, while staying well inside the replay window we are protecting.
const clockStepThreshold = 15 * time.Second

var processStart = time.Now()

// Clock is a wall clock with an optional one-shot correction applied on top.
// Now is safe for concurrent use and cheap enough for the packet path, so it
// can be assigned straight to an obfuscator's `clock func() time.Time` field.
//
// The correction it carries comes from an unauthenticated source; see the
// package documentation for what it may and may not be used for.
type Clock struct {
	mu         sync.RWMutex
	corrected  bool
	offset     time.Duration
	anchorWall time.Time
	anchorMono time.Duration

	// wallNow and mono are injection points for tests. mono must be a
	// monotonic reading, unaffected by system clock changes.
	wallNow func() time.Time
	mono    func() time.Duration
}

// NewClock returns an uncorrected Clock, which reads exactly like time.Now
// until a correction is applied.
func NewClock() *Clock {
	return &Clock{
		wallNow: time.Now,
		mono:    func() time.Duration { return time.Since(processStart) },
	}
}

// Now returns the current time, corrected if a correction is in effect.
func (c *Clock) Now() time.Time {
	// Monotonic readings must be stripped: a Time that carries one compares
	// against another such Time via the monotonic clock, which would make an
	// external step to the system clock invisible below.
	wall := c.wallNow().Round(0)

	c.mu.RLock()
	corrected, offset, anchorWall, anchorMono := c.corrected, c.offset, c.anchorWall, c.anchorMono
	c.mu.RUnlock()
	if !corrected {
		return wall
	}

	// Once we hand the device a working tunnel, its own ntp client gets to run
	// and steps the system clock to the right time. Keeping our offset on top
	// of that would double the correction and break the device a second time,
	// so a step we did not make means the system clock is now the better of
	// the two and ours is retired.
	expected := anchorWall.Add(c.mono() - anchorMono)
	if diff := wall.Sub(expected); diff > clockStepThreshold || diff < -clockStepThreshold {
		c.release()
		return wall
	}
	return wall.Add(offset)
}

// Correct applies offset to every subsequent Now, replacing any previous
// correction.
func (c *Clock) Correct(offset time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.corrected = true
	c.offset = offset
	c.anchorWall = c.wallNow().Round(0)
	c.anchorMono = c.mono()
}

// Offset reports the correction currently in effect, zero if none is.
func (c *Clock) Offset() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.offset
}

// Corrected reports whether a correction is currently in effect, as of the
// last call to Now — that is where an externally stepped system clock is
// noticed and the correction dropped.
func (c *Clock) Corrected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.corrected
}

func (c *Clock) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.corrected = false
	c.offset = 0
}
