package mimic

import (
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeMimic stands in for a Mimic process: it stays up until it is told to
// crash, or until the instance stops it.
type fakeMimic struct {
	exited  chan struct{}
	once    sync.Once
	stopped bool
}

func (f *fakeMimic) crash() { f.once.Do(func() { close(f.exited) }) }

func (f *fakeMimic) process() *process {
	return &process{
		wait: func() error {
			<-f.exited
			return errors.New("crashed")
		},
		stop: func() error {
			f.stopped = true
			f.crash()
			return nil
		},
	}
}

// fakeLauncher records every launch and hands out fakeMimics.
type fakeLauncher struct {
	mu       sync.Mutex
	started  []*fakeMimic
	launched chan *fakeMimic
	fail     int // number of leading attempts that fail
}

func newFakeLauncher() *fakeLauncher {
	return &fakeLauncher{launched: make(chan *fakeMimic, 16)}
}

func (l *fakeLauncher) launch() (*process, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail > 0 {
		l.fail--
		return nil, errors.New("no such interface")
	}
	f := &fakeMimic{exited: make(chan struct{})}
	l.started = append(l.started, f)
	l.launched <- f
	return f.process(), nil
}

func (l *fakeLauncher) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.started)
}

// next returns the next Mimic to be launched, failing the test if none is.
func (l *fakeLauncher) next(t *testing.T) *fakeMimic {
	t.Helper()
	select {
	case f := <-l.launched:
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mimic to be launched")
		return nil
	}
}

func testStart(t *testing.T, l *fakeLauncher) *Instance {
	t.Helper()
	i, err := startWithBackoff(l.launch, zap.NewNop(), time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("startWithBackoff: %v", err)
	}
	return i
}

func TestInstanceRestartsAfterCrash(t *testing.T) {
	l := newFakeLauncher()
	i := testStart(t, l)
	defer i.Close()

	first := l.next(t)
	first.crash()

	second := l.next(t)
	if second == first {
		t.Fatal("expected a new mimic after the crash")
	}
	// The replacement is the one Close has to stop.
	if err := i.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !second.stopped {
		t.Fatal("Close did not stop the restarted mimic")
	}
}

func TestInstanceSurvivesFailedRestarts(t *testing.T) {
	l := newFakeLauncher()
	i := testStart(t, l)
	defer i.Close()

	first := l.next(t)
	l.mu.Lock()
	l.fail = 3
	l.mu.Unlock()
	first.crash()

	// Attempts that fail must not end the supervision: it keeps trying until
	// one succeeds.
	if second := l.next(t); second == first {
		t.Fatal("expected a new mimic after the failed attempts")
	}
	if n := l.count(); n != 2 {
		t.Fatalf("expected 2 successful launches, got %d", n)
	}
}

func TestCloseStopsRestarting(t *testing.T) {
	l := newFakeLauncher()
	i := testStart(t, l)

	first := l.next(t)
	if err := i.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !first.stopped {
		t.Fatal("Close did not stop mimic")
	}
	// Close stops Mimic itself, which must not read as a crash to recover from.
	time.Sleep(50 * time.Millisecond)
	if n := l.count(); n != 1 {
		t.Fatalf("mimic was launched %d times, want 1", n)
	}
}

func TestCloseDuringRestartDelay(t *testing.T) {
	l := newFakeLauncher()
	// A delay far longer than the test would tolerate, so a Close that waits
	// it out fails the test rather than merely slowing it down.
	i, err := startWithBackoff(l.launch, zap.NewNop(), time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("startWithBackoff: %v", err)
	}
	l.next(t).crash()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = i.Close()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked until the restart delay elapsed")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	l := newFakeLauncher()
	i := testStart(t, l)
	l.next(t)

	if err := i.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := i.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCloseNilInstance(t *testing.T) {
	// Start returns a nil Instance when Mimic is disabled or already running
	// on the interface, and callers defer Close on it unconditionally.
	var i *Instance
	if err := i.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
