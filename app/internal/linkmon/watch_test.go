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
	"testing"
	"time"
)

// TestPlatformWatcherStartsAndStops runs the real thing on whatever this is
// being built for: it opens the kernel notification socket, then cancels and
// requires the monitor to shut down. Whether an actual interface change is
// delivered cannot be tested here — it would need the test to take the
// machine's network down — so the delivery path is covered by the fake
// watcher tests and only the setup and teardown are exercised for real.
//
// The teardown half is the part worth guarding: every platform's watcher
// blocks in a read that only a Close can interrupt, and a mistake there is
// invisible except as a goroutine that never exits.
func TestPlatformWatcherStartsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := New(Config{})
	events := m.Watch(ctx)

	src, err := m.Source()
	if src == "" {
		t.Fatal("Source() is empty after Watch")
	}
	if platformWatch != nil && src != platformSource {
		t.Errorf("Source() = %q (%v), want the platform watcher %q", src, err, platformSource)
	}
	t.Logf("source %q, err %v", src, err)

	cancel()
	select {
	case _, ok := <-events:
		if ok {
			// A change during the test is possible; drain and require the
			// close right after.
			select {
			case _, ok := <-events:
				if ok {
					t.Fatal("still delivering events after cancellation")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("event channel was not closed after cancellation")
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event channel was not closed after cancellation")
	}
}
