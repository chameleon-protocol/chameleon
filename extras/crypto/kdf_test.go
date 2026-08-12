package crypto

import (
	"bytes"
	"testing"
)

func TestStretchPasswordRejectsShortPasswords(t *testing.T) {
	if _, err := StretchPassword([]byte("abc"), ""); err != ErrPasswordTooShort {
		t.Errorf("got %v, want ErrPasswordTooShort", err)
	}
	if _, err := StretchPassword([]byte("abcd"), ""); err != nil {
		t.Errorf("4 bytes should be accepted, got %v", err)
	}
}

func TestStretchPasswordIsDeterministic(t *testing.T) {
	// Both ends derive independently with no handshake, so equal inputs must
	// give equal keys or the two sides simply cannot talk.
	a, err := StretchPassword([]byte("a_reasonable_password"), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := StretchPassword([]byte("a_reasonable_password"), "")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("same password gave different root keys")
	}
}

func TestRealmSeparatesDeployments(t *testing.T) {
	// The point of realm: one precomputed table must not cover every
	// deployment that happened to pick the same password.
	plain, err := StretchPassword([]byte("shared_password"), "")
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := StretchPassword([]byte("shared_password"), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	other, err := StretchPassword([]byte("shared_password"), "elsewhere.net")
	if err != nil {
		t.Fatal(err)
	}
	if plain == scoped || scoped == other || plain == other {
		t.Error("different realms produced the same root key")
	}
}

func TestDeriveSubkeySeparatesContexts(t *testing.T) {
	root, err := StretchPassword([]byte("a_reasonable_password"), "")
	if err != nil {
		t.Fatal(err)
	}
	c2s, err := DeriveSubkey(root, CtxSalamanderV2C2S, 32)
	if err != nil {
		t.Fatal(err)
	}
	s2c, err := DeriveSubkey(root, CtxSalamanderV2S2C, 32)
	if err != nil {
		t.Fatal(err)
	}
	padding, err := DeriveSubkey(root, CtxAppPadding, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c2s, s2c) {
		t.Error("the two directions share a key; a reflected packet would authenticate")
	}
	if bytes.Equal(c2s, padding) || bytes.Equal(s2c, padding) {
		t.Error("padding shares a key with the obfuscation layer")
	}
}

func TestDeriveSubkeyIsDeterministic(t *testing.T) {
	root, err := StretchPassword([]byte("a_reasonable_password"), "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := DeriveSubkey(root, CtxSalamanderV2C2S, 32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveSubkey(root, CtxSalamanderV2C2S, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("same context gave different subkeys")
	}
}

// BenchmarkStretchPasswordCold is the number that matters for the Argon2
// parameters: it is paid once per process on a fast machine, but on every
// reconnect if the cache is ever removed, and on router-class hardware it runs
// without assembly.
func BenchmarkStretchPasswordCold(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		// Vary the password so every iteration misses the cache.
		pw := []byte("benchmark_password_" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)))
		if _, err := StretchPassword(pw, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStretchPasswordCached(b *testing.B) {
	pw := []byte("benchmark_password_cached")
	if _, err := StretchPassword(pw, ""); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := StretchPassword(pw, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveSubkey(b *testing.B) {
	root, err := StretchPassword([]byte("benchmark_password"), "")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := DeriveSubkey(root, CtxSalamanderV2C2S, 32); err != nil {
			b.Fatal(err)
		}
	}
}
