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

package linkmon

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Change is a bitmask describing what moved. Consumers normally react to any
// non-zero value the same way — re-enumerate — and use the bits for logging.
type Change uint8

const (
	// ChangeLink is an interface appearing, disappearing, or flipping its
	// up/running state.
	ChangeLink Change = 1 << iota
	// ChangeAddr is an address being added to or removed from an interface.
	ChangeAddr
)

func (c Change) String() string {
	switch c {
	case 0:
		return "none"
	case ChangeLink:
		return "link"
	case ChangeAddr:
		return "addr"
	case ChangeLink | ChangeAddr:
		return "link|addr"
	default:
		return "unknown"
	}
}

// Event is one coalesced report that the network attachment moved.
type Event struct {
	// Changes is the union of everything observed during the burst.
	Changes Change
	// At is when the burst was considered settled. For an event that was
	// merged into an undelivered one it is the later of the two settle
	// times, i.e. always the freshest information available.
	At time.Time
	// Count is how many raw notifications went into this event. It is
	// observability only, but a Count in the hundreds is a good hint that
	// something on the box is flapping.
	Count int
}

// Source names the mechanism a Monitor is using to learn about changes.
type Source string

// SourcePolling is the fallback: the interface list is enumerated on a timer
// and diffed.
const SourcePolling Source = "polling"

// platformWatch and platformSource are set by the per-OS files in this
// package. A platform with no file leaves platformWatch nil, which is not a
// bug — it means the monitor polls there, which is the documented fallback.
//
// platformWatch blocks until ctx is done (returning nil) or the underlying
// mechanism fails (returning why).
var (
	platformWatch  func(ctx context.Context, raw chan<- Change) error
	platformSource Source
)

var errNoPlatformWatcher = errors.New("no native link change notification on this platform")

const (
	// DefaultDebounce is how long to wait for the notification burst to go
	// quiet before reporting. Long enough to swallow the dozen-odd
	// notifications a handover produces, short enough to leave most of the
	// one-second budget to the candidate enumeration and probing that follow.
	DefaultDebounce = 250 * time.Millisecond

	// DefaultMaxDelay bounds the wait when the notifications never go quiet —
	// a flapping link, or a router whose kernel talks constantly. Without it
	// the quiet period is a livelock: every new notification pushes the
	// deadline out and the consumer is never told anything at all.
	DefaultMaxDelay = 750 * time.Millisecond

	// DefaultPollInterval is the cadence of the fallback. One round is a
	// handful of syscalls — an interface dump plus a per-interface address
	// query — which is sub-millisecond on anything this runs on, so 2s is
	// invisible in CPU terms while bounding detection latency at 2s where
	// there is nothing better available.
	DefaultPollInterval = 2 * time.Second
)

// rawBufferSize is how many un-debounced notifications may be in flight
// between the watcher and the debounce loop. It only has to absorb the burst
// that arrives while the loop is busy handing an event to a slow consumer.
const rawBufferSize = 32

// Config tunes a Monitor. The zero value is valid and uses the defaults
// above.
type Config struct {
	// Debounce is the quiet period that ends a burst.
	Debounce time.Duration
	// MaxDelay caps how long an event may be held back from the start of a
	// burst, regardless of how busy the burst stays.
	MaxDelay time.Duration
	// PollInterval is the cadence of the polling fallback.
	PollInterval time.Duration
	// ForcePolling skips the platform's native watcher. For operators whose
	// kernel refuses the notification sockets, and for tests.
	ForcePolling bool
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.Debounce <= 0 {
		out.Debounce = DefaultDebounce
	}
	if out.MaxDelay <= 0 {
		out.MaxDelay = DefaultMaxDelay
	}
	if out.MaxDelay < out.Debounce {
		// A cap below the quiet period would emit mid-burst on every
		// notification, which is the behaviour debouncing exists to avoid.
		out.MaxDelay = out.Debounce
	}
	if out.PollInterval <= 0 {
		out.PollInterval = DefaultPollInterval
	}
	return out
}

// Monitor watches the machine's network attachment. Create one with New and
// start it with Watch.
type Monitor struct {
	cfg Config

	once sync.Once
	out  chan Event

	mu        sync.Mutex
	source    Source
	sourceErr error

	// Injection points for tests. now and after are the clock; watch and
	// enumerate are the two sources of raw notifications.
	now         func() time.Time
	after       func(time.Duration) <-chan time.Time
	watch       func(ctx context.Context, raw chan<- Change) error
	watchSource Source
	enumerate   func() (map[string]ifaceState, error)
}

// New returns a Monitor that has not started watching yet.
func New(cfg Config) *Monitor {
	return &Monitor{
		cfg:         cfg.withDefaults(),
		now:         time.Now,
		after:       time.After,
		watch:       platformWatch,
		watchSource: platformSource,
		enumerate:   enumerateInterfaces,
	}
}

// Watch starts watching and returns the channel of coalesced events. The
// channel is closed when ctx is done. Calling Watch more than once returns
// the same channel and ignores the later contexts — a Monitor watches for one
// context, create another Monitor if you need another.
func (m *Monitor) Watch(ctx context.Context) <-chan Event {
	m.once.Do(func() {
		// Settle the source before anything starts, so that a caller that
		// logs it right after Watch does not race the goroutines below.
		m.setSource(m.initialSource())
		m.out = make(chan Event, 1)
		raw := make(chan Change, rawBufferSize)
		go m.produce(ctx, raw)
		go m.loop(ctx, raw, m.out)
	})
	return m.out
}

// Source reports which mechanism is delivering notifications and, when it is
// not the platform's native one, why. Both are meaningful only after Watch,
// and both may change while running: a native watcher that dies is replaced
// by the polling fallback. Log it, so that a degraded monitor is visible
// before the day it has to be fast.
func (m *Monitor) Source() (Source, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.source, m.sourceErr
}

func (m *Monitor) setSource(src Source, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.source, m.sourceErr = src, err
}

func (m *Monitor) initialSource() (Source, error) {
	switch {
	case m.cfg.ForcePolling:
		return SourcePolling, nil
	case m.watch == nil:
		return SourcePolling, errNoPlatformWatcher
	default:
		return m.watchSource, nil
	}
}

// produce feeds raw with un-debounced notifications, from the native watcher
// if there is one and from the poller otherwise. A native watcher that fails
// — at startup or halfway through — demotes the monitor to polling for good
// rather than taking the whole monitor down with it: a slow notification is
// worth incomparably more than none.
func (m *Monitor) produce(ctx context.Context, raw chan<- Change) {
	defer close(raw)
	if !m.cfg.ForcePolling && m.watch != nil {
		err := m.watch(ctx, raw)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			// The watcher returned without the context being done, which
			// means the mechanism stopped for a reason it did not name.
			err = errors.New("native link watcher stopped unexpectedly")
		}
		m.setSource(SourcePolling, err)
	}
	m.poll(ctx, raw)
}

func (m *Monitor) loop(ctx context.Context, raw <-chan Change, out chan Event) {
	defer close(out)
	var (
		pending Change
		count   int
		burst   time.Time
		timer   <-chan time.Time
	)
	for {
		select {
		case <-ctx.Done():
			return
		case c, ok := <-raw:
			if !ok {
				return
			}
			if c == 0 {
				continue
			}
			if count == 0 {
				burst = m.now()
			}
			pending |= c
			count++
			// Re-arm on every notification: the burst is over when it goes
			// quiet, not a fixed time after it started. The previous timer is
			// abandoned rather than stopped; nothing reads it any more, and
			// at these rates the garbage is irrelevant.
			timer = m.after(m.delay(burst))
		case <-timer:
			timer = nil
			m.emit(ctx, out, Event{Changes: pending, At: m.now(), Count: count})
			pending, count = 0, 0
		}
	}
}

// delay is how long to wait for the burst that began at burst to go quiet,
// clamped so that the report never lands later than MaxDelay after the start.
func (m *Monitor) delay(burst time.Time) time.Duration {
	d := m.cfg.Debounce
	if rem := m.cfg.MaxDelay - m.now().Sub(burst); rem < d {
		d = rem
	}
	if d < 0 {
		d = 0
	}
	return d
}

// emit hands ev to the consumer. The channel holds one event, and when it is
// occupied the two are merged instead of one being dropped or the loop
// blocking: dropping would lose a change permanently, and blocking would stop
// the loop from draining the watcher. Merging costs the consumer nothing,
// because the only correct reaction to any event is to re-enumerate, and the
// union says everything the two events said.
func (m *Monitor) emit(ctx context.Context, out chan Event, ev Event) {
	for {
		select {
		case out <- ev:
			return
		case old := <-out:
			ev.Changes |= old.Changes
			ev.Count += old.Count
		case <-ctx.Done():
			return
		}
	}
}
