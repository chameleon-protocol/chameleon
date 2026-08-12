package obfs

import (
	"bytes"
	"testing"
	"time"
)

// pair builds a client and a server sharing a password, with a clock the test
// drives. Returns them in that order.
func pair(t *testing.T, password, realm string, now *time.Time) (*salamanderV2, *salamanderV2) {
	t.Helper()
	client, err := NewSalamanderV2([]byte(password), realm, RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSalamanderV2([]byte(password), realm, RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	if now != nil {
		clk := func() time.Time { return *now }
		client.now, server.now = clk, clk
		client.bootTime, server.bootTime = now.Add(-time.Hour), now.Add(-time.Hour)
	}
	return client, server
}

func TestSalamanderV2RoundTrip(t *testing.T) {
	client, server := pair(t, "a_reasonable_password", "", nil)
	payload := []byte("a QUIC datagram would go here")

	wire := make([]byte, len(payload)+smV2Overhead)
	n := client.Obfuscate(payload, wire)
	if n != len(payload)+smV2Overhead {
		t.Fatalf("Obfuscate wrote %d bytes, want %d", n, len(payload)+smV2Overhead)
	}

	out := make([]byte, 2048)
	got := server.Deobfuscate(wire[:n], out)
	if got != len(payload) {
		t.Fatalf("Deobfuscate returned %d, want %d", got, len(payload))
	}
	if !bytes.Equal(out[:got], payload) {
		t.Errorf("round trip changed the payload: %q", out[:got])
	}
}

// TestSalamanderV2ReplayIsRejected is the acceptance criterion for the whole
// rewrite: a recorded packet replayed verbatim must produce nothing. Under v1
// it decrypted cleanly every time, so the server answered and thereby
// identified itself.
func TestSalamanderV2ReplayIsRejected(t *testing.T) {
	client, server := pair(t, "a_reasonable_password", "", nil)
	payload := []byte("client initial")

	wire := make([]byte, len(payload)+smV2Overhead)
	n := client.Obfuscate(payload, wire)
	recorded := bytes.Clone(wire[:n])

	out := make([]byte, 2048)
	if got := server.Deobfuscate(bytes.Clone(recorded), out); got != len(payload) {
		t.Fatalf("first delivery should succeed, got %d", got)
	}
	for i := range 3 {
		if got := server.Deobfuscate(bytes.Clone(recorded), out); got != 0 {
			t.Errorf("replay %d produced %d bytes, want 0", i+1, got)
		}
	}
}

// Legitimate QUIC retransmissions must not be caught by the replay set. They
// are safe because the salt is generated fresh inside Obfuscate, so the same
// payload sent twice is two different packets on the wire.
func TestSalamanderV2RetransmissionIsNotAReplay(t *testing.T) {
	client, server := pair(t, "a_reasonable_password", "", nil)
	payload := []byte("retransmitted verbatim by QUIC")

	out := make([]byte, 2048)
	for i := range 5 {
		wire := make([]byte, len(payload)+smV2Overhead)
		n := client.Obfuscate(payload, wire)
		if got := server.Deobfuscate(wire[:n], out); got != len(payload) {
			t.Fatalf("resend %d was rejected (got %d bytes)", i, got)
		}
	}
}

func TestSalamanderV2RejectsTamperedPackets(t *testing.T) {
	client, server := pair(t, "a_reasonable_password", "", nil)
	payload := []byte("authenticate me")
	wire := make([]byte, len(payload)+smV2Overhead)
	n := client.Obfuscate(payload, wire)
	out := make([]byte, 2048)

	for _, pos := range []int{0, smV2SaltLen, n - 1} {
		tampered := bytes.Clone(wire[:n])
		tampered[pos] ^= 0x01
		if got := server.Deobfuscate(tampered, out); got != 0 {
			t.Errorf("flipping a bit at %d still decoded (%d bytes)", pos, got)
		}
	}
}

func TestSalamanderV2RejectsGarbageAndShortPackets(t *testing.T) {
	_, server := pair(t, "a_reasonable_password", "", nil)
	out := make([]byte, 2048)
	for _, size := range []int{0, 1, smV2MinLen - 1, smV2MinLen, 100, 1400} {
		junk := make([]byte, size)
		for i := range junk {
			junk[i] = byte(i)
		}
		if got := server.Deobfuscate(junk, out); got != 0 {
			t.Errorf("%d bytes of junk decoded to %d bytes", size, got)
		}
	}
}

func TestSalamanderV2WrongPasswordOrRealm(t *testing.T) {
	client, _ := pair(t, "correct_password", "", nil)
	_, otherPassword := pair(t, "wrong_password", "", nil)
	_, otherRealm := pair(t, "correct_password", "somewhere.else", nil)

	payload := []byte("secret")
	wire := make([]byte, len(payload)+smV2Overhead)
	n := client.Obfuscate(payload, wire)
	out := make([]byte, 2048)

	if got := otherPassword.Deobfuscate(bytes.Clone(wire[:n]), out); got != 0 {
		t.Errorf("wrong password decoded %d bytes", got)
	}
	if got := otherRealm.Deobfuscate(bytes.Clone(wire[:n]), out); got != 0 {
		t.Errorf("wrong realm decoded %d bytes", got)
	}
}

// Directional keys mean a packet cannot be reflected: sending a client's packet
// back to another client, or a server's packet to a server, must fail.
func TestSalamanderV2ReflectionIsRejected(t *testing.T) {
	client, _ := pair(t, "a_reasonable_password", "", nil)
	otherClient, _ := pair(t, "a_reasonable_password", "", nil)

	payload := []byte("bounce me")
	wire := make([]byte, len(payload)+smV2Overhead)
	n := client.Obfuscate(payload, wire)

	out := make([]byte, 2048)
	if got := otherClient.Deobfuscate(bytes.Clone(wire[:n]), out); got != 0 {
		t.Errorf("a client accepted another client's packet (%d bytes)", got)
	}
}

func TestSalamanderV2TimestampWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	client, server := pair(t, "a_reasonable_password", "", &now)
	payload := []byte("timestamped")
	out := make([]byte, 2048)

	seal := func() []byte {
		wire := make([]byte, len(payload)+smV2Overhead)
		n := client.Obfuscate(payload, wire)
		return wire[:n]
	}

	tooOld := seal()
	now = now.Add(smV2MaxSkew + 5*time.Second)
	if got := server.Deobfuscate(tooOld, out); got != 0 {
		t.Errorf("a packet older than the skew allowance was accepted (%d bytes)", got)
	}

	fromTheFuture := seal()
	now = now.Add(-(smV2MaxSkew + 5*time.Second))
	if got := server.Deobfuscate(fromTheFuture, out); got != 0 {
		t.Errorf("a packet from beyond the skew allowance was accepted (%d bytes)", got)
	}

	current := seal()
	if got := server.Deobfuscate(current, out); got != len(payload) {
		t.Errorf("a current packet was rejected (%d bytes)", got)
	}
}

// A restart empties the replay set while the timestamp window still accepts the
// last 30 seconds, which would hand the oracle straight back. The boot barrier
// refuses anything predating startup until the process has been up long enough
// for the replay set to cover the window by itself.
func TestSalamanderV2BootBarrier(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	client, _ := pair(t, "a_reasonable_password", "", &now)

	payload := []byte("recorded before the restart")
	wire := make([]byte, len(payload)+smV2Overhead)
	n := client.Obfuscate(payload, wire)
	recorded := bytes.Clone(wire[:n])

	// The server restarts five seconds later: fresh replay set, empty.
	now = now.Add(5 * time.Second)
	restarted, err := NewSalamanderV2([]byte("a_reasonable_password"), "", RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return now }
	restarted.bootTime = now

	out := make([]byte, 2048)
	if got := restarted.Deobfuscate(bytes.Clone(recorded), out); got != 0 {
		t.Errorf("a packet recorded before the restart was accepted (%d bytes); "+
			"the replay oracle is back", got)
	}

	// Once uptime exceeds the skew allowance the barrier lifts, and packets
	// minted after boot are accepted normally.
	now = now.Add(smV2MaxSkew + time.Second)
	fresh := make([]byte, len(payload)+smV2Overhead)
	client.now = func() time.Time { return now }
	fn := client.Obfuscate(payload, fresh)
	if got := restarted.Deobfuscate(fresh[:fn], out); got != len(payload) {
		t.Errorf("a fresh packet was rejected after the barrier lifted (%d bytes)", got)
	}
}

func TestReplaySetRetainsAcrossRotation(t *testing.T) {
	r := newReplaySet()
	now := time.Unix(1_800_000_000, 0)
	var salt [smV2SaltLen]byte
	salt[0] = 0xAA

	if r.seenOrAdd(salt, now) {
		t.Fatal("first sighting reported as a replay")
	}
	// Two periods on: still inside the retention window.
	if !r.seenOrAdd(salt, now.Add(2*replayPeriod)) {
		t.Error("forgot a salt while it was still replayable")
	}
	// Past every bucket: forgetting is correct here, and by then the timestamp
	// window has closed on it anyway.
	if r.seenOrAdd(salt, now.Add(5*replayPeriod)) {
		t.Log("salt forgotten after full rotation, as designed")
	}
}

func TestSalamanderV2OutputBounds(t *testing.T) {
	client, server := pair(t, "a_reasonable_password", "", nil)
	payload := []byte("bounds")

	// Obfuscate must refuse rather than overrun a short destination.
	short := make([]byte, len(payload)+smV2Overhead-1)
	if n := client.Obfuscate(payload, short); n != 0 {
		t.Errorf("Obfuscate wrote %d bytes into a buffer too small for it", n)
	}

	wire := make([]byte, len(payload)+smV2Overhead)
	n := client.Obfuscate(payload, wire)
	tooSmall := make([]byte, len(payload)-1)
	if got := server.Deobfuscate(wire[:n], tooSmall); got != 0 {
		t.Errorf("Deobfuscate wrote %d bytes into a buffer too small for it", got)
	}
}

func BenchmarkSalamanderV2Obfuscate(b *testing.B) {
	client, err := NewSalamanderV2([]byte("benchmark_password"), "", RoleClient)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1400)
	out := make([]byte, 2048)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		if client.Obfuscate(payload, out) == 0 {
			b.Fatal("Obfuscate failed")
		}
	}
}

func BenchmarkSalamanderV2Deobfuscate(b *testing.B) {
	client, err := NewSalamanderV2([]byte("benchmark_password"), "", RoleClient)
	if err != nil {
		b.Fatal(err)
	}
	server, err := NewSalamanderV2([]byte("benchmark_password"), "", RoleServer)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1400)
	out := make([]byte, 2048)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		wire := make([]byte, len(payload)+smV2Overhead)
		n := client.Obfuscate(payload, wire)
		if server.Deobfuscate(wire[:n], out) == 0 {
			b.Fatal("Deobfuscate failed")
		}
	}
}
