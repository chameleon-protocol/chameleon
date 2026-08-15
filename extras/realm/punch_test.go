package realm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/chameleon-protocol/chameleon/extras/v2/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPunchPacketEncodeDecode(t *testing.T) {
	meta := testPunchMetadata()
	mask := testMask

	for _, packetType := range []PunchPacketType{PunchPacketHello, PunchPacketAck} {
		t.Run(packetTypeName(packetType), func(t *testing.T) {
			packet, err := EncodePunchPacket(packetType, meta, mask)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(packet), punchMinWireLen)
			assert.LessOrEqual(t, len(packet), punchMaxWireLen)
			assert.False(t, bytes.Contains(packet, punchMagic[:]))

			decoded, err := DecodePunchPacket(packet, meta, mask)
			require.NoError(t, err)
			assert.Equal(t, packetType, decoded.Type)
			assert.Equal(t, len(packet)-punchMinWireLen, decoded.PaddingLength)
		})
	}
}

func TestPunchPacketRejectsWrongNonce(t *testing.T) {
	meta := testPunchMetadata()
	mask := testMask
	packet, err := EncodePunchPacket(PunchPacketHello, meta, mask)
	require.NoError(t, err)

	_, err = DecodePunchPacket(packet, PunchMetadata{
		Nonce: "ffffffffffffffffffffffffffffffff",
	}, mask)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
	assert.Contains(t, err.Error(), "nonce mismatch")
}

// A packet masked with another realm's key must not even reach the nonce
// comparison: the magic is what stands between an unknown packet and the demux.
func TestPunchPacketRejectsWrongMask(t *testing.T) {
	meta := testPunchMetadata()
	packet, err := EncodePunchPacket(PunchPacketHello, meta, testMask)
	require.NoError(t, err)

	other, err := NewPunchMask([]byte("another-realm-password"), "")
	require.NoError(t, err)
	_, err = DecodePunchPacket(packet, meta, other)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad magic")
}

func TestPunchPacketRequiresMask(t *testing.T) {
	meta := testPunchMetadata()

	_, err := EncodePunchPacket(PunchPacketHello, meta, PunchMask{})
	require.ErrorIs(t, err, ErrPunchMaskRequired)

	packet, err := EncodePunchPacket(PunchPacketHello, meta, testMask)
	require.NoError(t, err)
	_, err = DecodePunchPacket(packet, meta, PunchMask{})
	require.ErrorIs(t, err, ErrPunchMaskRequired)
}

// The mask key must not be an obfuscation key: both layers sit on the same
// socket and derive from the same password, and a shared key there is one
// keystream serving two formats.
//
// Only the derivation context separates them, so the check has to be against
// the keys the obfuscator actually derives -- same password, same realm, same
// root -- not against another punch mask. Swapping crypto.CtxPunchMask for
// crypto.CtxSalamanderV2C2S in NewPunchMask makes the mask bit-identical to the
// obfuscator's client-to-server subkey, and that is what this fails on.
func TestPunchMaskIsNotTheObfsKey(t *testing.T) {
	const (
		password  = "realm-password"
		realmName = "deployment"
	)
	mask, err := NewPunchMask([]byte(password), realmName)
	require.NoError(t, err)
	require.Len(t, mask.key, punchMaskKeyLen)

	root, err := crypto.StretchPassword([]byte(password), realmName)
	require.NoError(t, err)
	for _, ctx := range []string{
		crypto.CtxSalamanderV2C2S,
		crypto.CtxSalamanderV2S2C,
		crypto.CtxSalamanderV2Root,
		crypto.CtxAppPadding,
	} {
		obfsKey, err := crypto.DeriveSubkey(root, ctx, punchMaskKeyLen)
		require.NoError(t, err)
		assert.NotEqualf(t, obfsKey, mask.key, "the punch mask is the %q subkey", ctx)
	}
	// The root itself is not a subkey of anything, so it needs its own compare.
	assert.NotEqual(t, root[:], mask.key, "the punch mask is the stretched password")
}

// The realm has to reach the derivation, or two deployments that picked the
// same obfuscation password would mask their punch packets alike and each could
// read the other's.
func TestPunchMaskIsScopedToTheRealm(t *testing.T) {
	scoped, err := NewPunchMask([]byte("realm-password"), "deployment")
	require.NoError(t, err)
	elsewhere, err := NewPunchMask([]byte("realm-password"), "elsewhere")
	require.NoError(t, err)
	unscoped, err := NewPunchMask([]byte("realm-password"), "")
	require.NoError(t, err)
	assert.NotEqual(t, scoped.key, elsewhere.key)
	assert.NotEqual(t, scoped.key, unscoped.key)
}

func TestPunchPacketSaltVariesWireBytes(t *testing.T) {
	meta := testPunchMetadata()
	mask := testMask
	a, err := EncodePunchPacket(PunchPacketHello, meta, mask)
	require.NoError(t, err)
	b, err := EncodePunchPacket(PunchPacketHello, meta, mask)
	require.NoError(t, err)
	assert.NotEqual(t, a[:punchSaltLen], b[:punchSaltLen])
	assert.NotEqual(t, a, b)
}

// This is the property the clear-text attempt tag did not have, and the one it
// was measured on: over the packets of a single attempt, no byte offset carries
// a value that repeats. The tag was a constant four bytes at offset 8, which
// made "some 4-byte value at offset 8 repeats three times" a complete detector
// at 100% / 0.00% false positives.
//
// The threshold is a multiple-comparison bound, not a feel. Each of the
// wireLen*256 = 307200 (offset, value) cells holds a Binomial(256, 1/256) count
// over uniformly random bytes -- mean 1 -- and the test fails if any one of
// them exceeds maxRepeat. At maxRepeat=10 the per-cell tail is 8.4e-9, so a run
// trips on the random tail with probability 2.6e-3: measured at 2 failures in
// 400 runs, which is where this number came from. At 20 the tail is 8.0e-20 and
// the per-run figure is 2.4e-14.
//
// Raising the bound costs almost no detection power, because what it is looking
// for is not near it. A field that is constant across the attempt sits at 256
// of 256, and so does one that is merely mask-independent: dropping
// xorPunchHeader leaves the magic in the clear at 256, and a zeroed salt makes
// the whole masked header constant at 256.
func TestPunchPacketRepeatsNoBytes(t *testing.T) {
	const (
		packets   = 256
		wireLen   = 1200
		maxRepeat = 20
	)
	key, err := newPunchKey(testPunchMetadata(), testMask)
	require.NoError(t, err)

	counts := make([][256]int, wireLen)
	for range packets {
		packet, err := encodePunchPacket(PunchPacketHello, key, wireLen)
		require.NoError(t, err)
		require.Len(t, packet, wireLen)
		for offset, b := range packet {
			counts[offset][b]++
		}
	}
	for offset, byteCounts := range counts {
		worst, value := 0, 0
		for b, n := range byteCounts {
			if n > worst {
				worst, value = n, b
			}
		}
		require.LessOrEqualf(t, worst, maxRepeat,
			"offset %d carries 0x%02x in %d of %d packets", offset, value, worst, packets)
	}
}

func TestPunchPacketRejectsCorruptedPacket(t *testing.T) {
	meta := testPunchMetadata()
	mask := testMask
	packet, err := EncodePunchPacket(PunchPacketAck, meta, mask)
	require.NoError(t, err)
	packet[0] ^= 0xff

	_, err = DecodePunchPacket(packet, meta, mask)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketRejectsBadLengths(t *testing.T) {
	meta := testPunchMetadata()
	mask := testMask

	_, err := DecodePunchPacket(make([]byte, punchMinWireLen-1), meta, mask)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))

	_, err = DecodePunchPacket(make([]byte, punchMaxWireLen+1), meta, mask)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketRejectsUnknownType(t *testing.T) {
	meta := testPunchMetadata()
	mask := testMask
	key, err := newPunchKey(meta, mask)
	require.NoError(t, err)

	packet := make([]byte, punchMinWireLen)
	copy(packet[:punchSaltLen], []byte("12345678"))
	header := packet[punchSaltLen:]
	copy(header[:len(punchMagic)], punchMagic[:])
	header[len(punchMagic)] = 0xff
	copy(header[len(punchMagic)+1:], key.nonce[:])
	xorPunchHeader(header, mask, packet[:punchSaltLen])

	_, err = DecodePunchPacket(packet, meta, mask)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPunchPacket)
	assert.Contains(t, err.Error(), "unknown packet type")
}

func TestPunchPacketRejectsBadMetadata(t *testing.T) {
	mask := testMask
	_, err := EncodePunchPacket(PunchPacketHello, PunchMetadata{Nonce: "not-hex"}, mask)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))

	_, err = EncodePunchPacket(PunchPacketHello, PunchMetadata{Nonce: "0011"}, mask)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

// Without a sample the length is a guess, and two things are worth pinning: it
// is not a band of its own, and it is not a single length either. The bounds
// are external facts, not this package's constants: 1200 is the smallest
// datagram a QUIC endpoint may send an Initial in (RFC 9000 §14.1), 1472 is
// what fits an Ethernet MTU over IPv4, and [33,1057] is the range the uniform
// padding this replaces produced, which was measured at 99-100% detection on
// wire length alone.
//
// The second assertion is the one the predecessor test carried and this one
// nearly lost. A fallback that returns a constant is the fixed-target mistake
// the design rejects by name -- 1250 was measured as a beacon -- and every
// bound above still holds while it happens, so only the count of distinct
// lengths catches it. Over 256 draws from a 194-wide band, seeing one length is
// a 194^-255 event.
func TestPunchPacketFallbackLengthLandsInTheQUICBand(t *testing.T) {
	meta := testPunchMetadata()
	mask := testMask
	seen := map[int]struct{}{}
	for range 256 {
		packet, err := EncodePunchPacket(PunchPacketHello, meta, mask)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(packet), 1200)
		assert.LessOrEqual(t, len(packet), 1473)
		seen[len(packet)] = struct{}{}
	}
	assert.Greater(t, len(seen), 1, "every fallback packet came out the same length")
}

func testPunchMetadata() PunchMetadata {
	return PunchMetadata{
		Nonce: "00112233445566778899aabbccddeeff",
		Obfs:  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
}

// testMask is the realm mask every punch test in this package uses. It is a
// package-level value because deriving it stretches a password on purpose, and
// every punch entry point now needs one.
var testMask = mustTestPunchMask()

func mustTestPunchMask() PunchMask {
	mask, err := NewPunchMask([]byte("test-realm-password"), "test")
	if err != nil {
		panic(err)
	}
	return mask
}

func packetTypeName(packetType PunchPacketType) string {
	switch packetType {
	case PunchPacketHello:
		return "hello"
	case PunchPacketAck:
		return "ack"
	default:
		return "unknown"
	}
}
