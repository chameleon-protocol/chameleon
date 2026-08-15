package realm

import (
	"bytes"
	"errors"
	"testing"

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

// The mask key must not be the obfuscation key itself: the punch layer and the
// obfuscation layer sit on the same socket, and a shared key there means a
// keystream reused across two formats.
func TestPunchMaskIsNotTheObfsKey(t *testing.T) {
	mask, err := NewPunchMask([]byte("realm-password"), "deployment")
	require.NoError(t, err)
	other, err := NewPunchMask([]byte("realm-password"), "")
	require.NoError(t, err)
	assert.NotEqual(t, mask.key, other.key)
	assert.Len(t, mask.key, punchMaskKeyLen)
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
// at 100% / 0.00% false positives (docs/design/p1-punch-envelope.md).
//
// Uniformly random bytes put the expected modal count at one per offset over
// 256 packets; a constant field puts it at 256. The threshold sits far from
// both, so this fails on any offset that keeps a value across packets and does
// not flake on the random tail.
func TestPunchPacketRepeatsNoBytes(t *testing.T) {
	const (
		packets   = 256
		wireLen   = 1200
		maxRepeat = 10
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

// Without a sample the length is a guess, and the only thing worth pinning is
// that it is not a band of its own. The bounds are external facts, not this
// package's constants: 1200 is the smallest datagram a QUIC endpoint may send
// an Initial in (RFC 9000 §14.1), 1472 is what fits an Ethernet MTU over IPv4,
// and [33,1057] is the range the uniform padding this replaces produced, which
// was measured at 99-100% detection on wire length alone.
func TestPunchPacketFallbackLengthLandsInTheQUICBand(t *testing.T) {
	meta := testPunchMetadata()
	mask := testMask
	for range 256 {
		packet, err := EncodePunchPacket(PunchPacketHello, meta, mask)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(packet), 1200)
		assert.LessOrEqual(t, len(packet), 1472)
	}
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
