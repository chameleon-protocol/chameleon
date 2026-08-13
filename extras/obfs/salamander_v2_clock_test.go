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

package obfs

import (
	"testing"
	"time"
)

const clockTestPassword = "a_reasonable_password"

// A host with no RTC boots at the Unix epoch, so every packet it sends is
// decades outside the peer's window and nothing it does connects. WithClock is
// how a correction fetched out of band reaches the obfuscator; without it the
// obfuscator is stuck on the system clock that is the problem.
func TestSalamanderV2WithClockKeepsPacketsInWindow(t *testing.T) {
	now := time.Now()
	fixed := func() time.Time { return now }
	epoch := func() time.Time { return time.Unix(0, 0) }

	server, err := NewSalamanderV2([]byte(clockTestPassword), "", RoleServer, WithClock(fixed))
	if err != nil {
		t.Fatal(err)
	}
	corrected, err := NewSalamanderV2([]byte(clockTestPassword), "", RoleClient, WithClock(fixed))
	if err != nil {
		t.Fatal(err)
	}
	uncorrected, err := NewSalamanderV2([]byte(clockTestPassword), "", RoleClient, WithClock(epoch))
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("a QUIC datagram would go here")
	wire := make([]byte, len(payload)+smV2Overhead)
	out := make([]byte, 2048)

	n := corrected.Obfuscate(payload, wire)
	if got := server.Deobfuscate(wire[:n], out); got != len(payload) {
		t.Errorf("corrected clock: peer accepted %d bytes, want %d", got, len(payload))
	}
	n = uncorrected.Obfuscate(payload, wire)
	if got := server.Deobfuscate(wire[:n], out); got != 0 {
		t.Errorf("clock at the epoch: peer accepted %d bytes, want 0", got)
	}
}

// The boot barrier has to be anchored to the same clock the timestamps are, or
// it silently switches itself off on exactly the hosts WithClock exists for.
// A corrected clock reads far ahead of the system clock that was never set; if
// boot were stamped with the latter, the receiver would believe it has been up
// for decades, lift the barrier, and reopen the restart replay window that
// Salamander v2 exists to close.
func TestSalamanderV2WithClockAnchorsBootBarrier(t *testing.T) {
	// Ahead of the real system clock by far more than the skew allowance,
	// which is the shape of a correction landing on an RTC-less host.
	base := time.Now().Add(365 * 24 * time.Hour)
	receiver, err := NewSalamanderV2([]byte(clockTestPassword), "", RoleServer,
		WithClock(func() time.Time { return base }))
	if err != nil {
		t.Fatal(err)
	}
	// Ten seconds before the receiver booted: inside the ±30s window, but the
	// receiver's replay set cannot possibly have seen it, so it must be
	// refused until the process has been up long enough to cover the window.
	sender, err := NewSalamanderV2([]byte(clockTestPassword), "", RoleClient,
		WithClock(func() time.Time { return base.Add(-10 * time.Second) }))
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("recorded before the restart")
	wire := make([]byte, len(payload)+smV2Overhead)
	out := make([]byte, 2048)
	n := sender.Obfuscate(payload, wire)
	if got := receiver.Deobfuscate(wire[:n], out); got != 0 {
		t.Errorf("pre-boot timestamp accepted %d bytes, want 0", got)
	}
}

// A nil clock is not a way to break the obfuscator: it keeps the system clock.
func TestSalamanderV2WithNilClockIsIgnored(t *testing.T) {
	o, err := NewSalamanderV2([]byte(clockTestPassword), "", RoleClient, WithClock(nil))
	if err != nil {
		t.Fatal(err)
	}
	if drift := time.Since(o.now()); drift > time.Minute || drift < -time.Minute {
		t.Errorf("clock is %v away from the system clock, want the system clock", drift)
	}
}
