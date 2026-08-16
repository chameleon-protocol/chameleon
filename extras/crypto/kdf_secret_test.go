package crypto

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// A 32-byte stand-in for a TLS exporter's output. Nothing here depends on where
// it came from; that is the point of taking it as bytes.
var testSecret = []byte("an-exporter-output-32-bytes-long")

func TestDeriveFromSecretRejectsShortSecrets(t *testing.T) {
	// 32 is written out rather than referred to: an assertion whose expected
	// value is the constant it guards asserts nothing. A secret shorter than
	// this has fewer bits in it than the key material expanded from it appears
	// to have, and nothing downstream can tell.
	if MinSecretLen != 32 {
		t.Errorf("MinSecretLen = %d, want 32", MinSecretLen)
	}
	if len(testSecret) != 32 {
		t.Fatalf("the test's secret is %d bytes", len(testSecret))
	}
	if _, err := DeriveFromSecret(testSecret[:31], CtxDiscoTagC2S, 32); err != ErrSecretTooShort {
		t.Errorf("31-byte secret: err = %v, want ErrSecretTooShort", err)
	}
	if _, err := DeriveFromSecret(nil, CtxDiscoTagC2S, 32); err != ErrSecretTooShort {
		t.Errorf("nil secret: err = %v, want ErrSecretTooShort", err)
	}
	if _, err := DeriveFromSecret(testSecret, CtxDiscoTagC2S, 32); err != nil {
		t.Errorf("32-byte secret: %v", err)
	}
}

func TestDeriveFromSecretIsDeterministicAndSized(t *testing.T) {
	// Both ends derive independently with no handshake, so equal inputs must
	// give equal keys or the two sides simply cannot talk.
	first, err := DeriveFromSecret(testSecret, CtxDiscoBodyC2S, 32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveFromSecret(testSecret, CtxDiscoBodyC2S, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("the same secret and context gave different keys")
	}
	for _, n := range []int{8, 32, 64} {
		b, err := DeriveFromSecret(testSecret, CtxDiscoProbe, n)
		if err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		if len(b) != n {
			t.Errorf("length %d: got %d bytes", n, len(b))
		}
	}
}

// A different secret is a different connection, and must share nothing. A
// reconnect derives a new exporter secret, so a packet from the old connection
// must not be routable to the new one.
func TestDeriveFromSecretSeparatesSecrets(t *testing.T) {
	other := append([]byte(nil), testSecret...)
	other[0] ^= 1
	a, err := DeriveFromSecret(testSecret, CtxDiscoTagC2S, 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveFromSecret(other, CtxDiscoTagC2S, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two secrets differing in one bit produced the same key")
	}
}

// discoContexts is every context the disco key schedule expands, with the
// string each one must keep.
//
// The literals are here rather than referenced from the constants on purpose.
// These are protocol constants: both ends derive with no handshake to negotiate
// over, so editing one in place silently breaks every deployment that has not
// upgraded, and the rule is that a change comes with a version bump in the name.
// A test that compared each constant to itself would let that edit through.
var discoContexts = map[string]string{
	"CtxDiscoTagC2S":  "chameleon/realm/disco-v1/tag/c2s",
	"CtxDiscoTagS2C":  "chameleon/realm/disco-v1/tag/s2c",
	"CtxDiscoBodyC2S": "chameleon/realm/disco-v1/body/c2s",
	"CtxDiscoBodyS2C": "chameleon/realm/disco-v1/body/s2c",
	"CtxDiscoProbe":   "chameleon/realm/disco-v1/probe",
	"CtxDiscoEpoch":   "chameleon/realm/disco-v1/epoch",
}

// allContexts is every derivation context as the code actually declares it.
// The distinctness checks read from here, never from the literals above, or
// they would test the test.
func allContexts() map[string]string {
	return map[string]string{
		"CtxSalamanderV2Root": CtxSalamanderV2Root,
		"CtxSalamanderV2C2S":  CtxSalamanderV2C2S,
		"CtxSalamanderV2S2C":  CtxSalamanderV2S2C,
		"CtxAppPadding":       CtxAppPadding,
		"CtxPunchMask":        CtxPunchMask,
		"CtxDiscoTagC2S":      CtxDiscoTagC2S,
		"CtxDiscoTagS2C":      CtxDiscoTagS2C,
		"CtxDiscoBodyC2S":     CtxDiscoBodyC2S,
		"CtxDiscoBodyS2C":     CtxDiscoBodyS2C,
		"CtxDiscoProbe":       CtxDiscoProbe,
		"CtxDiscoEpoch":       CtxDiscoEpoch,
	}
}

func TestDiscoContextsAreWhatTheProtocolSays(t *testing.T) {
	got := allContexts()
	for name, want := range discoContexts {
		if got[name] != want {
			t.Errorf("%s = %q, want %q -- a context edited in place is a silent wire break", name, got[name], want)
		}
	}
}

// The contexts exist to keep the keys apart. Everything below is one secret
// expanded six ways, and any two of them coming out equal is the failure the
// domain separation exists to prevent -- most sharply for the two directions,
// where a shared key means a packet reflected back at its sender authenticates.
func TestDerivationContextsProduceDistinctKeys(t *testing.T) {
	all := allContexts()
	keys := map[string][]byte{}
	for name, ctx := range all {
		b, err := DeriveFromSecret(testSecret, ctx, 32)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		keys[name] = b
	}
	for a, ka := range keys {
		for b, kb := range keys {
			if a < b && bytes.Equal(ka, kb) {
				t.Errorf("%s and %s expand to the same key", a, b)
			}
		}
	}

	// No context may be a prefix of another either. CtxDiscoEpoch is documented
	// as a prefix -- the epoch number is appended to it -- and if some other
	// context started with it, one epoch's tag key would collide with that
	// context's whole key.
	for a, ca := range all {
		for b, cb := range all {
			if a != b && strings.HasPrefix(cb, ca) {
				t.Errorf("%s (%q) is a prefix of %s (%q)", a, ca, b, cb)
			}
		}
	}
}

// The epoch context is the one used with a suffix, so the thing to check is that
// two epochs do not expand to the same key: the tag rotation exists to make a
// tag unlinkable across epochs, and it buys nothing if the epochs share it.
func TestDiscoEpochSuffixesSeparate(t *testing.T) {
	seen := map[string]uint64{}
	for epoch := uint64(14166664); epoch < 14166670; epoch++ {
		b, err := DeriveFromSecret(testSecret, CtxDiscoEpoch+"/"+strconv.FormatUint(epoch, 10), 8)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[string(b)]; dup {
			t.Errorf("epochs %d and %d expand to the same tag", prev, epoch)
		}
		seen[string(b)] = epoch
	}
	// And the bare prefix is not any epoch's key.
	bare, err := DeriveFromSecret(testSecret, CtxDiscoEpoch, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, dup := seen[string(bare)]; dup {
		t.Error("the epoch context with no epoch appended collides with an epoch's tag")
	}
}
