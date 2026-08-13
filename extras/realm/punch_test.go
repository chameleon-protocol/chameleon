package realm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPunchPacketEncodeDecode(t *testing.T) {
	meta := testPunchMetadata()

	for _, packetType := range []PunchPacketType{PunchPacketHello, PunchPacketAck} {
		t.Run(packetTypeName(packetType), func(t *testing.T) {
			packet, err := EncodePunchPacket(packetType, meta)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(packet), punchMinWireLen)
			assert.LessOrEqual(t, len(packet), punchMaxWireLen)
			assert.False(t, bytes.Contains(packet, punchMagic[:]))

			decoded, err := DecodePunchPacket(packet, meta)
			require.NoError(t, err)
			assert.Equal(t, packetType, decoded.Type)
			assert.Equal(t, len(packet)-punchMinWireLen, decoded.PaddingLength)
		})
	}
}

func TestPunchPacketRejectsWrongMetadata(t *testing.T) {
	meta := testPunchMetadata()
	packet, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)

	_, err = DecodePunchPacket(packet, PunchMetadata{
		Nonce: "ffffffffffffffffffffffffffffffff",
		Obfs:  meta.Obfs,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))

	_, err = DecodePunchPacket(packet, PunchMetadata{
		Nonce: meta.Nonce,
		Obfs:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketSaltVariesWireBytes(t *testing.T) {
	meta := testPunchMetadata()
	a, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	b, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	assert.NotEqual(t, a[:punchSaltLen], b[:punchSaltLen])
	assert.NotEqual(t, a, b)
}

func TestPunchPacketRejectsCorruptedPacket(t *testing.T) {
	meta := testPunchMetadata()
	packet, err := EncodePunchPacket(PunchPacketAck, meta)
	require.NoError(t, err)
	packet[0] ^= 0xff

	_, err = DecodePunchPacket(packet, meta)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketRejectsBadLengths(t *testing.T) {
	meta := testPunchMetadata()

	_, err := DecodePunchPacket(make([]byte, punchMinWireLen-1), meta)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))

	_, err = DecodePunchPacket(make([]byte, punchMaxWireLen+1), meta)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketRejectsUnknownType(t *testing.T) {
	meta := testPunchMetadata()
	key, err := newPunchKey(meta)
	require.NoError(t, err)

	packet := make([]byte, punchMinWireLen)
	copy(packet[:punchSaltLen], []byte("12345678"))
	binary.BigEndian.PutUint32(packet[punchSaltLen:punchSaltLen+punchTagLen], key.tag)
	plain := packet[punchSaltLen+punchTagLen:]
	copy(plain[:len(punchMagic)], punchMagic[:])
	plain[len(punchMagic)] = 0xff
	copy(plain[len(punchMagic)+1:punchHeaderLen], key.nonce)
	xorPunchPacket(plain, key.obfsKey, packet[:punchSaltLen])

	_, err = DecodePunchPacket(packet, meta)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPunchPacket)
	assert.Contains(t, err.Error(), "unknown packet type")
}

// The attempt tag is what lets the demux find the attempt in one lookup, so it
// has to be on the wire, stable per attempt, and different between attempts.
func TestPunchPacketTagIdentifiesAttempt(t *testing.T) {
	meta := testPunchMetadata()
	key, err := newPunchKey(meta)
	require.NoError(t, err)

	for range 8 {
		packet, err := EncodePunchPacket(PunchPacketHello, meta)
		require.NoError(t, err)
		tag, ok := punchPacketTag(packet)
		require.True(t, ok)
		assert.Equal(t, key.tag, tag)
	}

	other, err := newPunchKey(PunchMetadata{
		Nonce: "ffffffffffffffffffffffffffffffff",
		Obfs:  meta.Obfs,
	})
	require.NoError(t, err)
	assert.NotEqual(t, key.tag, other.tag)
}

func TestPunchPacketTagMismatchIsCheap(t *testing.T) {
	meta := testPunchMetadata()
	packet, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	// Corrupting the tag must be rejected on the tag alone: the demux relies on
	// a wrong tag never reaching the obfuscation layer.
	packet[punchSaltLen] ^= 0xff

	_, err = DecodePunchPacket(packet, meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tag mismatch")
}

func TestPunchPacketRejectsBadMetadata(t *testing.T) {
	_, err := EncodePunchPacket(PunchPacketHello, PunchMetadata{
		Nonce: "not-hex",
		Obfs:  testPunchMetadata().Obfs,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))

	_, err = EncodePunchPacket(PunchPacketHello, PunchMetadata{
		Nonce: testPunchMetadata().Nonce,
		Obfs:  "not-hex",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketPaddingVaries(t *testing.T) {
	meta := testPunchMetadata()
	seen := make(map[int]struct{})
	for range 64 {
		packet, err := EncodePunchPacket(PunchPacketHello, meta)
		require.NoError(t, err)
		decoded, err := DecodePunchPacket(packet, meta)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, decoded.PaddingLength, 0)
		assert.LessOrEqual(t, decoded.PaddingLength, MaxPunchPadding)
		seen[decoded.PaddingLength] = struct{}{}
	}
	assert.Greater(t, len(seen), 1)
}

func testPunchMetadata() PunchMetadata {
	return PunchMetadata{
		Nonce: "00112233445566778899aabbccddeeff",
		Obfs:  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
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
