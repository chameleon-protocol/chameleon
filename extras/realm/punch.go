package realm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

const (
	MaxPunchPadding = 1024

	punchSaltLen = 8
	// punchTagLen is the attempt tag: a per-attempt value derived from the
	// metadata, sent in the clear so the demux can find the attempt with a map
	// lookup instead of trial-decrypting every packet against every attempt.
	// See punchAttemptTag for why that trade is worth making.
	punchTagLen = 4
	// Plain punch payload before obfs:
	// 8-byte magic, 1-byte type, 16-byte nonce, then 0..1024 random padding bytes.
	punchHeaderLen  = 25
	punchMinWireLen = punchSaltLen + punchTagLen + punchHeaderLen
	punchMaxWireLen = punchMinWireLen + MaxPunchPadding

	// punchTagContext domain-separates the attempt tag from every other value
	// derived from the punch metadata.
	punchTagContext = "chameleon/punch-tag-v1"
)

var (
	ErrInvalidPunchPacket = errors.New("invalid punch packet")

	// Bumped to v2 with the attempt tag: a v1 packet decodes to a different
	// layout, so the magic makes the mismatch explicit instead of surfacing as
	// a nonce mismatch on every packet.
	punchMagic = [8]byte{'C', 'H', 'R', 'L', 'M', 'v', '2', 0}
)

type PunchPacketType byte

const (
	PunchPacketHello PunchPacketType = 0x01
	PunchPacketAck   PunchPacketType = 0x02
)

type PunchPacket struct {
	Type          PunchPacketType
	PaddingLength int
}

// punchKey is the decoded, pre-hashed form of PunchMetadata. Decoding hex and
// hashing the tag once per attempt instead of once per packet is what keeps the
// demux cheap when punching runs for the lifetime of the socket.
type punchKey struct {
	nonce   []byte
	obfsKey []byte
	tag     uint32
}

func newPunchKey(meta PunchMetadata) (punchKey, error) {
	nonce, obfsKey, err := decodePunchMetadata(meta)
	if err != nil {
		return punchKey{}, err
	}
	return punchKey{
		nonce:   nonce,
		obfsKey: obfsKey,
		tag:     punchAttemptTag(nonce, obfsKey),
	}, nil
}

// punchAttemptTag derives the clear-text attempt tag from the punch metadata.
//
// It is the one part of the packet that is not masked, which costs some
// unlinkability: an observer can tell that two packets belong to the same
// attempt. That is already true from the address pair alone, and the metadata
// the tag is derived from is relayed in the clear by the rendezvous server
// anyway (see the package documentation). What it buys is that a packet from an
// unknown source costs one map lookup rather than one SHA-256 and one compare
// per in-flight attempt — the difference between a bounded cost and an
// attacker-controlled multiplier now that punching outlives the handshake.
func punchAttemptTag(nonce, obfsKey []byte) uint32 {
	h := sha256.New()
	_, _ = h.Write([]byte(punchTagContext))
	_, _ = h.Write(nonce)
	_, _ = h.Write(obfsKey)
	return binary.BigEndian.Uint32(h.Sum(nil)[:punchTagLen])
}

func EncodePunchPacket(packetType PunchPacketType, meta PunchMetadata) ([]byte, error) {
	key, err := newPunchKey(meta)
	if err != nil {
		return nil, err
	}
	return encodePunchPacket(packetType, key)
}

func encodePunchPacket(packetType PunchPacketType, key punchKey) ([]byte, error) {
	if !validPunchPacketType(packetType) {
		return nil, fmt.Errorf("%w: unknown packet type", ErrInvalidPunchPacket)
	}
	paddingLength, err := randomPaddingLength()
	if err != nil {
		return nil, err
	}
	plain := make([]byte, punchHeaderLen+paddingLength)
	copy(plain[:len(punchMagic)], punchMagic[:])
	plain[len(punchMagic)] = byte(packetType)
	copy(plain[len(punchMagic)+1:punchHeaderLen], key.nonce)
	if paddingLength > 0 {
		if _, err := rand.Read(plain[punchHeaderLen:]); err != nil {
			return nil, err
		}
	}
	packet := make([]byte, punchSaltLen+punchTagLen+len(plain))
	if _, err := rand.Read(packet[:punchSaltLen]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(packet[punchSaltLen:punchSaltLen+punchTagLen], key.tag)
	body := packet[punchSaltLen+punchTagLen:]
	copy(body, plain)
	xorPunchPacket(body, key.obfsKey, packet[:punchSaltLen])
	return packet, nil
}

func DecodePunchPacket(packet []byte, meta PunchMetadata) (PunchPacket, error) {
	key, err := newPunchKey(meta)
	if err != nil {
		return PunchPacket{}, err
	}
	return decodePunchPacket(packet, key)
}

func decodePunchPacket(packet []byte, key punchKey) (PunchPacket, error) {
	tag, ok := punchPacketTag(packet)
	if !ok {
		return PunchPacket{}, fmt.Errorf("%w: packet too short", ErrInvalidPunchPacket)
	}
	if len(packet) > punchMaxWireLen {
		return PunchPacket{}, fmt.Errorf("%w: packet too long", ErrInvalidPunchPacket)
	}
	if tag != key.tag {
		return PunchPacket{}, fmt.Errorf("%w: tag mismatch", ErrInvalidPunchPacket)
	}
	salt := packet[:punchSaltLen]
	plain := append([]byte(nil), packet[punchSaltLen+punchTagLen:]...)
	xorPunchPacket(plain, key.obfsKey, salt)
	if !bytes.Equal(plain[:len(punchMagic)], punchMagic[:]) {
		return PunchPacket{}, fmt.Errorf("%w: bad magic", ErrInvalidPunchPacket)
	}
	packetType := PunchPacketType(plain[len(punchMagic)])
	if !validPunchPacketType(packetType) {
		return PunchPacket{}, fmt.Errorf("%w: unknown packet type", ErrInvalidPunchPacket)
	}
	if !bytes.Equal(plain[len(punchMagic)+1:punchHeaderLen], key.nonce) {
		return PunchPacket{}, fmt.Errorf("%w: nonce mismatch", ErrInvalidPunchPacket)
	}
	return PunchPacket{
		Type:          packetType,
		PaddingLength: len(plain) - punchHeaderLen,
	}, nil
}

// punchPacketTag reads the attempt tag off the wire. It is the only thing the
// demux needs before it knows which attempt a packet belongs to.
func punchPacketTag(packet []byte) (uint32, bool) {
	if len(packet) < punchMinWireLen {
		return 0, false
	}
	return binary.BigEndian.Uint32(packet[punchSaltLen : punchSaltLen+punchTagLen]), true
}

func decodePunchMetadata(meta PunchMetadata) (nonce, obfsKey []byte, err error) {
	nonce, err = decodeHexSize("nonce", meta.Nonce, PunchNonceSize)
	if err != nil {
		return nil, nil, err
	}
	obfsKey, err = decodeHexSize("obfs", meta.Obfs, PunchObfsKeySize)
	if err != nil {
		return nil, nil, err
	}
	return nonce, obfsKey, nil
}

func decodeHexSize(name, value string, size int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s", ErrInvalidPunchPacket, name)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%w: invalid %s length", ErrInvalidPunchPacket, name)
	}
	return b, nil
}

func randomPaddingLength() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(MaxPunchPadding+1))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func xorPunchPacket(packet, obfsKey, salt []byte) {
	h := sha256.New()
	_, _ = h.Write(obfsKey)
	_, _ = h.Write(salt)
	mask := h.Sum(nil)
	for i := range packet {
		packet[i] ^= mask[i%len(mask)]
	}
}

func validPunchPacketType(packetType PunchPacketType) bool {
	return packetType == PunchPacketHello || packetType == PunchPacketAck
}
