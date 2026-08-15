package realm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/chameleon-protocol/chameleon/extras/v2/crypto"
)

const (
	punchSaltLen = 8
	// Plain punch header: 8-byte magic, 1-byte type, 16-byte nonce. The whole
	// header has to fit in one SHA-256 output, see xorPunchHeader.
	punchHeaderLen  = 8 + 1 + PunchNonceSize
	punchMinWireLen = punchSaltLen + punchHeaderLen
	// punchMaxWireLen is the largest datagram that fits an Ethernet MTU without
	// fragmenting on IPv4. Punch packets take their length from the packets the
	// socket is already sending (see PunchPacketConn.sampleWireLen), and those
	// come out of path MTU discovery, so this only has to be an upper bound on
	// what the socket can legitimately send.
	punchMaxWireLen = 1472
	// MaxPunchPadding is what is left for padding at the largest wire length.
	MaxPunchPadding = punchMaxWireLen - punchMinWireLen

	punchMaskKeyLen = 32

	// A punch packet sent before the socket has carried anything else has no
	// sample to copy. This band covers what such a socket sends next: a QUIC
	// Initial padded to quic-go's InitialPacketSize (1280) plus whatever the
	// obfuscator adds (32 bytes for salamander v2), through a full datagram
	// after path MTU discovery has run (measured at 1439 plain / 1471 obfs).
	//
	// The limit of this fallback should be stated plainly: it overlaps real
	// traffic instead of forming a band of its own, which is the mistake a fixed
	// 1250 makes, but it cannot hit the modal length, so a classifier that has
	// learned this deployment's exact lengths offline still flags these packets.
	// Only a sample fixes that, and the initiator has none before its first QUIC
	// packet -- it punches on a bare socket, so nothing has passed through the
	// sampler yet.
	punchFallbackMinLen = 1280
	punchFallbackMaxLen = punchMaxWireLen
)

var (
	ErrInvalidPunchPacket = errors.New("invalid punch packet")
	// ErrPunchMaskRequired is what a punch attempt without a realm mask key
	// fails with. There is no unmasked punch format: under obfs.type plain the
	// best measured envelope still showed 50% (c2s) / 24% (s2c) detection, so
	// the missing key is a configuration error, never a downgrade.
	ErrPunchMaskRequired = errors.New("punch requires an obfuscation password")

	// v3 drops the clear-text attempt tag and keys the mask off the realm
	// password instead of the relayed per-attempt key. A v2 packet decodes to a
	// different layout under a key its sender never had, so the magic makes the
	// mismatch explicit instead of surfacing as a nonce that matches nobody.
	punchMagic = [8]byte{'C', 'H', 'R', 'L', 'M', 'v', '3', 0}
)

// The header is masked with a single SHA-256 output, so it must fit in one.
// A pad repeated over a longer buffer is what salamander v1 died of: with the
// magic as known plaintext, the repeat would hand an observer the keystream
// (see extras/obfs/salamander_v2.go).
var _ [sha256.Size - punchHeaderLen]struct{}

type PunchPacketType byte

const (
	PunchPacketHello PunchPacketType = 0x01
	PunchPacketAck   PunchPacketType = 0x02
)

type PunchPacket struct {
	Type          PunchPacketType
	PaddingLength int
}

// PunchMask is the realm-wide key that masks punch packets.
//
// It is realm-wide rather than per-attempt on purpose: the receiver has to
// unmask before it knows which attempt a packet belongs to, and a per-attempt
// key would mean one trial decryption per registered attempt per inbound
// packet. That cost is attacker-controlled -- anyone who can send UDP to the
// port triggers it -- and with attempts counted per concurrently connecting
// client it reaches hundreds. See docs/design/p1-punch-envelope.md.
//
// The zero value carries no key and is rejected by every entry point.
type PunchMask struct {
	key []byte
}

// NewPunchMask derives the punch mask key from the obfuscation password.
//
// password and realmName are the obfuscator's, not the rendezvous server's:
// the rendezvous server relays punch metadata verbatim and must not be able to
// mask or unmask a punch packet. The realm here is the obfs deployment scope
// (obfs.salamanderV2.realm), which is a different thing from the realm ID in
// the rendezvous URL.
//
// The root key is shared with the obfuscator and the subkey context is not, so
// the mask is independent of the obfuscation keys derived from the same
// password. StretchPassword caches, so the Argon2id cost is paid once per
// process no matter how many times this is called.
func NewPunchMask(password []byte, realmName string) (PunchMask, error) {
	root, err := crypto.StretchPassword(password, realmName)
	if err != nil {
		return PunchMask{}, err
	}
	key, err := crypto.DeriveSubkey(root, crypto.CtxPunchMask, punchMaskKeyLen)
	if err != nil {
		return PunchMask{}, err
	}
	return PunchMask{key: key}, nil
}

func (m PunchMask) valid() bool {
	return len(m.key) == punchMaskKeyLen
}

func (m PunchMask) equal(other PunchMask) bool {
	return bytes.Equal(m.key, other.key)
}

// punchKey is the decoded form of one attempt's punch metadata, plus the realm
// mask every attempt on the socket shares.
type punchKey struct {
	nonce [PunchNonceSize]byte
	mask  PunchMask
}

func newPunchKey(meta PunchMetadata, mask PunchMask) (punchKey, error) {
	if !mask.valid() {
		return punchKey{}, ErrPunchMaskRequired
	}
	nonce, err := decodeHexSize("nonce", meta.Nonce, PunchNonceSize)
	if err != nil {
		return punchKey{}, err
	}
	key := punchKey{mask: mask}
	copy(key.nonce[:], nonce)
	return key, nil
}

// punchHeader is what one unmask yields: enough to decide whether the packet is
// a punch packet at all, and if so which attempt it belongs to.
type punchHeader struct {
	packetType PunchPacketType
	nonce      [PunchNonceSize]byte
}

func EncodePunchPacket(packetType PunchPacketType, meta PunchMetadata, mask PunchMask) ([]byte, error) {
	key, err := newPunchKey(meta, mask)
	if err != nil {
		return nil, err
	}
	wireLen, err := fallbackPunchWireLen()
	if err != nil {
		return nil, err
	}
	return encodePunchPacket(packetType, key, wireLen)
}

// encodePunchPacket writes one punch packet of exactly wireLen bytes.
//
// The length is the caller's because it is not ours to randomise: sealing does
// not hide length, and padding drawn from a distribution of its own is a
// distinguisher on every packet (uniform [33,1057] was measured at 99-100%
// detection). The caller is expected to hand over a length this socket has
// already sent.
func encodePunchPacket(packetType PunchPacketType, key punchKey, wireLen int) ([]byte, error) {
	if !validPunchPacketType(packetType) {
		return nil, fmt.Errorf("%w: unknown packet type", ErrInvalidPunchPacket)
	}
	if !key.mask.valid() {
		return nil, ErrPunchMaskRequired
	}
	packet := make([]byte, clampPunchWireLen(wireLen))
	// Salt and padding are both random, so they are drawn together. The padding
	// is deliberately not masked: XORing a keystream over random bytes changes
	// nothing an observer can see, and generating enough keystream to cover a
	// 1472-byte packet would cost the send path 40-odd SHA-256 blocks.
	if _, err := rand.Read(packet); err != nil {
		return nil, err
	}
	header := packet[punchSaltLen : punchSaltLen+punchHeaderLen]
	copy(header, punchMagic[:])
	header[len(punchMagic)] = byte(packetType)
	copy(header[len(punchMagic)+1:], key.nonce[:])
	xorPunchHeader(header, key.mask, packet[:punchSaltLen])
	return packet, nil
}

func DecodePunchPacket(packet []byte, meta PunchMetadata, mask PunchMask) (PunchPacket, error) {
	key, err := newPunchKey(meta, mask)
	if err != nil {
		return PunchPacket{}, err
	}
	return decodePunchPacket(packet, key)
}

func decodePunchPacket(packet []byte, key punchKey) (PunchPacket, error) {
	header, err := unmaskPunchHeader(packet, key.mask)
	if err != nil {
		return PunchPacket{}, err
	}
	if header.nonce != key.nonce {
		return PunchPacket{}, fmt.Errorf("%w: nonce mismatch", ErrInvalidPunchPacket)
	}
	return PunchPacket{
		Type:          header.packetType,
		PaddingLength: len(packet) - punchMinWireLen,
	}, nil
}

// unmaskPunchHeader is the entire per-packet cost of the demux: one SHA-256, a
// magic compare, and a 16-byte nonce to look the attempt up by. It does not
// depend on how many attempts are registered, which is the whole point of
// masking with a realm key instead of a per-attempt one.
//
// A packet that is not ours fails the magic compare, and an attacker without
// the realm password cannot produce one that does not.
func unmaskPunchHeader(packet []byte, mask PunchMask) (punchHeader, error) {
	if !mask.valid() {
		return punchHeader{}, ErrPunchMaskRequired
	}
	if len(packet) < punchMinWireLen {
		return punchHeader{}, fmt.Errorf("%w: packet too short", ErrInvalidPunchPacket)
	}
	if len(packet) > punchMaxWireLen {
		return punchHeader{}, fmt.Errorf("%w: packet too long", ErrInvalidPunchPacket)
	}
	var header [punchHeaderLen]byte
	copy(header[:], packet[punchSaltLen:punchMinWireLen])
	xorPunchHeader(header[:], mask, packet[:punchSaltLen])
	if !bytes.Equal(header[:len(punchMagic)], punchMagic[:]) {
		return punchHeader{}, fmt.Errorf("%w: bad magic", ErrInvalidPunchPacket)
	}
	packetType := PunchPacketType(header[len(punchMagic)])
	if !validPunchPacketType(packetType) {
		return punchHeader{}, fmt.Errorf("%w: unknown packet type", ErrInvalidPunchPacket)
	}
	out := punchHeader{packetType: packetType}
	copy(out.nonce[:], header[len(punchMagic)+1:])
	return out, nil
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

func clampPunchWireLen(wireLen int) int {
	return min(max(wireLen, punchMinWireLen), punchMaxWireLen)
}

// fallbackPunchWireLen is for a socket with no samples yet. See the comment on
// punchFallbackMinLen for what it can and cannot do.
func fallbackPunchWireLen() (int, error) {
	n, err := randomUint(punchFallbackMaxLen - punchFallbackMinLen + 1)
	if err != nil {
		return 0, err
	}
	return punchFallbackMinLen + n, nil
}

// randomUint returns a value in [0,n). The modulo bias is at most one part in
// 2^24 for the ranges used here, and nothing this picks is key material.
func randomUint(n int) (int, error) {
	if n <= 1 {
		return 0, nil
	}
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	v := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	return int(v % uint32(n)), nil
}

func xorPunchHeader(header []byte, mask PunchMask, salt []byte) {
	h := sha256.New()
	_, _ = h.Write(mask.key)
	_, _ = h.Write(salt)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	for i := range header {
		header[i] ^= sum[i]
	}
}

func validPunchPacketType(packetType PunchPacketType) bool {
	return packetType == PunchPacketHello || packetType == PunchPacketAck
}
