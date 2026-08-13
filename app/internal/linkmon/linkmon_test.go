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
	"testing"
	"time"
)

// fakeClock drives the debounce loop without waiting for real time. After
// reports every arming on the armed channel, which is the only reliable way
// for a test to know that the loop has consumed a notification: without it,
// advancing the clock races the loop and fires a timer that has not been set
// yet.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer

	armed chan time.Duration
}

type fakeTimer struct {
	deadline time.Time
	ch       chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		now:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		armed: make(chan time.Duration, 1024),
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	t := &fakeTimer{deadline: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	c.armed <- d
	return t.ch
}

// advance moves the clock and fires every timer that has come due. Timers the
// loop abandoned when it re-armed still fire; nothing reads them.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var due []*fakeTimer
	kept := c.timers[:0]
	for _, t := range c.timers {
		if t.deadline.After(now) {
			kept = append(kept, t)
		} else {
			due = append(due, t)
		}
	}
	c.timers = kept
	c.mu.Unlock()
	for _, t := range due {
		t.ch <- now
	}
}

func (c *fakeClock) waitArmed(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-c.armed:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a timer to be armed")
		return 0
	}
}

// waitArmedFor waits for a timer armed for exactly want, ignoring the others.
// The poller and the debounce loop arm independently, so which of them gets
// there first is not something a test may assume.
func (c *fakeClock) waitArmedFor(t *testing.T, want time.Duration) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case d := <-c.armed:
			if d == want {
				return
			}
		case <-deadline:
			t.Fatalf("no timer was armed for %v", want)
		}
	}
}

// newTestMonitor returns a monitor on a fake clock whose notifications come
// from the returned channel instead of the kernel.
func newTestMonitor(t *testing.T, cfg Config) (*Monitor, *fakeClock, chan<- Change) {
	t.Helper()
	src := make(chan Change)
	m := New(cfg)
	clk := newFakeClock()
	m.now, m.after = clk.Now, clk.After
	m.watch = func(ctx context.Context, raw chan<- Change) error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case c := <-src:
				select {
				case raw <- c:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
	m.enumerate = func() (map[string]ifaceState, error) {
		return map[string]ifaceState{}, nil
	}
	return m, clk, src
}

func recvEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("event channel closed unexpectedly")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an event")
		return Event{}
	}
}

func TestBurstBecomesOneEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, clk, src := newTestMonitor(t, Config{Debounce: 250 * time.Millisecond, MaxDelay: 750 * time.Millisecond})
	events := m.Watch(ctx)

	// A handover looks like this: a few notifications in quick succession.
	for _, c := range []Change{ChangeAddr, ChangeLink, ChangeAddr, ChangeLink} {
		src <- c
		if d := clk.waitArmed(t); d != 250*time.Millisecond {
			t.Fatalf("armed for %v, want the full quiet period", d)
		}
	}
	clk.advance(250 * time.Millisecond)

	ev := recvEvent(t, events)
	if ev.Changes != ChangeLink|ChangeAddr {
		t.Errorf("Changes = %v, want link|addr", ev.Changes)
	}
	if ev.Count != 4 {
		t.Errorf("Count = %d, want 4", ev.Count)
	}
	select {
	case ev := <-events:
		t.Fatalf("burst produced a second event: %+v", ev)
	default:
	}
}

func TestNeverQuietBurstIsReportedAtMaxDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const debounce, maxDelay = 250 * time.Millisecond, 750 * time.Millisecond
	m, clk, src := newTestMonitor(t, Config{Debounce: debounce, MaxDelay: maxDelay})
	events := m.Watch(ctx)
	start := clk.Now()

	// A link that flaps faster than the quiet period must not be able to
	// defer the report forever.
	src <- ChangeLink
	clk.waitArmed(t)
	for i := 0; i < 3; i++ {
		clk.advance(200 * time.Millisecond)
		src <- ChangeAddr
		clk.waitArmed(t)
	}
	clk.advance(150 * time.Millisecond)

	ev := recvEvent(t, events)
	if got := ev.At.Sub(start); got != maxDelay {
		t.Errorf("event landed %v after the burst began, want %v", got, maxDelay)
	}
	if ev.Count != 4 {
		t.Errorf("Count = %d, want 4", ev.Count)
	}
}

func TestSlowConsumerLosesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, clk, src := newTestMonitor(t, Config{Debounce: 250 * time.Millisecond, MaxDelay: 750 * time.Millisecond})
	events := m.Watch(ctx)

	// First burst settles into the channel while nobody is reading.
	src <- ChangeLink
	clk.waitArmed(t)
	clk.advance(250 * time.Millisecond)

	// Second burst has to go somewhere: the channel already holds an event.
	src <- ChangeAddr
	clk.waitArmed(t) // also proves the first event has been handed over
	clk.advance(250 * time.Millisecond)

	// A third notification only serves as a barrier: the loop cannot arm
	// again until it has finished delivering the second event.
	src <- ChangeLink
	clk.waitArmed(t)

	ev := recvEvent(t, events)
	if ev.Changes != ChangeLink|ChangeAddr {
		t.Errorf("Changes = %v, want the union of both bursts", ev.Changes)
	}
	if ev.Count != 2 {
		t.Errorf("Count = %d, want both notifications accounted for", ev.Count)
	}
}

func TestChannelClosesWhenContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m, _, _ := newTestMonitor(t, Config{})
	events := m.Watch(ctx)
	cancel()

	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("got an event after cancellation, want the channel closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event channel was not closed after cancellation")
	}
}

func TestWatchTwiceReturnsTheSameChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, _, _ := newTestMonitor(t, Config{})
	if a, b := m.Watch(ctx), m.Watch(ctx); a != b {
		t.Fatal("second Watch returned a different channel")
	}
}

func TestPollingReportsWhatMoved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const poll = 2 * time.Second
	m, clk, _ := newTestMonitor(t, Config{
		Debounce:     250 * time.Millisecond,
		MaxDelay:     750 * time.Millisecond,
		PollInterval: poll,
		ForcePolling: true,
	})
	snapshots := newScriptedEnumerator(
		map[string]ifaceState{"en0": {index: 1, up: true, addrs: []string{"192.168.1.5/24"}}},
		map[string]ifaceState{
			"en0":    {index: 1, up: false, addrs: []string{}},
			"rmnet0": {index: 2, up: true, addrs: []string{"10.4.0.9/30"}},
		},
	)
	m.enumerate = snapshots.next
	events := m.Watch(ctx)

	if d := clk.waitArmed(t); d != poll {
		t.Fatalf("poller armed for %v, want the poll interval", d)
	}
	clk.advance(poll)
	clk.waitArmedFor(t, 250*time.Millisecond)
	clk.advance(250 * time.Millisecond)

	ev := recvEvent(t, events)
	if ev.Changes != ChangeLink|ChangeAddr {
		t.Errorf("Changes = %v, want link|addr for a WiFi to cellular move", ev.Changes)
	}
	if src, err := m.Source(); src != SourcePolling || err != nil {
		t.Errorf("Source() = %q, %v; want polling with no error", src, err)
	}
}

func TestNativeWatcherFailureFallsBackToPolling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const poll = 2 * time.Second
	m, clk, _ := newTestMonitor(t, Config{PollInterval: poll})
	boom := errors.New("netlink socket: permission denied")
	m.watch = func(context.Context, chan<- Change) error { return boom }
	snapshots := newScriptedEnumerator(
		map[string]ifaceState{"en0": {index: 1, up: true}},
		map[string]ifaceState{"en0": {index: 1, up: true, addrs: []string{"192.168.1.5/24"}}},
	)
	m.enumerate = snapshots.next
	events := m.Watch(ctx)

	// The poller arming is proof that the fallback took over.
	if d := clk.waitArmed(t); d != poll {
		t.Fatalf("armed for %v, want the poll interval", d)
	}
	src, err := m.Source()
	if src != SourcePolling {
		t.Errorf("Source() = %q, want polling", src)
	}
	if !errors.Is(err, boom) {
		t.Errorf("Source() error = %v, want the watcher's failure to be reported", err)
	}

	clk.advance(poll)
	clk.waitArmedFor(t, DefaultDebounce)
	clk.advance(DefaultDebounce)
	if ev := recvEvent(t, events); ev.Changes != ChangeAddr {
		t.Errorf("Changes = %v, want addr", ev.Changes)
	}
}

func TestNoNativeWatcherFallsBackToPolling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, clk, _ := newTestMonitor(t, Config{})
	m.watch = nil
	m.Watch(ctx)

	clk.waitArmed(t)
	src, err := m.Source()
	if src != SourcePolling {
		t.Errorf("Source() = %q, want polling", src)
	}
	if !errors.Is(err, errNoPlatformWatcher) {
		t.Errorf("Source() error = %v, want the missing watcher to be reported", err)
	}
}

func TestConfigDefaults(t *testing.T) {
	got := (&Config{}).withDefaults()
	if got.Debounce != DefaultDebounce || got.MaxDelay != DefaultMaxDelay || got.PollInterval != DefaultPollInterval {
		t.Errorf("zero Config = %+v, want the defaults", got)
	}
	// A cap below the quiet period would report mid-burst on every single
	// notification, which is what debouncing exists to prevent.
	got = (&Config{Debounce: time.Second, MaxDelay: time.Millisecond}).withDefaults()
	if got.MaxDelay != time.Second {
		t.Errorf("MaxDelay = %v, want it raised to the quiet period", got.MaxDelay)
	}
}

func TestChangeString(t *testing.T) {
	for _, tc := range []struct {
		c    Change
		want string
	}{
		{0, "none"},
		{ChangeLink, "link"},
		{ChangeAddr, "addr"},
		{ChangeLink | ChangeAddr, "link|addr"},
	} {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("Change(%d).String() = %q, want %q", tc.c, got, tc.want)
		}
	}
}

type scriptedEnumerator struct {
	mu        sync.Mutex
	snapshots []map[string]ifaceState
}

// newScriptedEnumerator hands out one snapshot per call, repeating the last
// one forever so that the poller settles instead of reporting changes on
// every round.
func newScriptedEnumerator(snapshots ...map[string]ifaceState) *scriptedEnumerator {
	return &scriptedEnumerator{snapshots: snapshots}
}

func (s *scriptedEnumerator) next() (map[string]ifaceState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.snapshots[0]
	if len(s.snapshots) > 1 {
		s.snapshots = s.snapshots[1:]
	}
	return cur, nil
}
