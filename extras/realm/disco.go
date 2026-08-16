package realm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/chameleon-protocol/chameleon/extras/v2/crypto"
)

// The disco envelope, as it goes on the wire:
//
//	offset  len  field
//	     0    8  tag         the per-session, per-epoch demultiplexing key
//	     8   12  nonce       crypto/rand, and the AEAD nonce
//	    20    N  ciphertext  ChaCha20-Poly1305 over header ‖ payload ‖ padding
//	  20+N   16  auth tag
//	                         aad = tag
//
// and the authenticated header inside it:
//
//	offset  len  field
//	     0    1  version     discoVersion
//	     1    1  type        DiscoType
//	     2    2  payloadLen  uint16, everything past it is padding
//	     4    4  ts          uint32 unix seconds
//	     8    4  seq         uint32, per sender, from 1
//
// The tag is clear text *within this envelope*, and that is only safe because
// the envelope never reaches the wire on its own. Disco sits above the
// obfuscator, so what a middlebox sees is this whole packet sealed again under
// the deployment's obfuscation key. That layering is not a preference: measured
// against a real captured flow, this exact byte layout put on the wire directly
// is caught by "does an 8-byte prefix repeat in this flow" at 100% detection and
// 0.00% false positives, on the first packet, in every deployment and both
// directions -- and enabling obfuscation underneath makes it *more* visible, not
// less, because salamander v2 turns the background into uniform random bytes and
// a constant prefix is then the only structure left in the flow. Sealed by the
// obfuscator instead, the same bytes score 0%, never caught.
//
// The clear-text tag buys the thing an AEAD-only format cannot have: an inbound
// datagram finds its session in one map lookup instead of one trial decryption
// per registered session. On a server that cost would be paid on every QUIC
// packet, multiplied by the number of live connections, and it would be
// attacker-controlled.
const (
	// discoVersion is the first byte of the authenticated header. It is checked
	// after the AEAD has opened, so only a peer holding this connection's key
	// can make it fail: a mismatch means the two ends disagree about the format,
	// never that someone is probing, which is why it is counted apart from the
	// other rejections.
	//
	// It shares no numbering with the punch envelope. Punch has no version byte
	// at all -- its header is an eight-byte magic followed by a type, where 0x01
	// is Hello -- and the two formats never meet, since they are demultiplexed
	// on opposite sides of the obfuscator under different keys. So the value is
	// free; it starts at 0x02 and there is no reason to renumber it.
	discoVersion byte = 0x02

	discoTagLen    = 8
	discoNonceLen  = chacha20poly1305.NonceSize
	discoSealLen   = chacha20poly1305.Overhead
	discoHeaderLen = 12
	discoKeyLen    = chacha20poly1305.KeySize

	// discoMinWire is the shortest packet this format can produce: envelope,
	// header, and no payload at all. A datagram below it cannot be disco, which
	// is the first and cheapest branch of the demultiplexer.
	discoMinWire = discoTagLen + discoNonceLen + discoHeaderLen + discoSealLen

	// discoMaxWire is quic-go's MaxPacketBufferSize. Disco is padded to a length
	// this connection's own QUIC datagrams take, and those cannot exceed it, so
	// the ceiling is a bound on a mistake rather than a shaping decision.
	discoMaxWire = 1452

	// DiscoBindNonceSize is the length of the challenge nonce a BIND carries.
	DiscoBindNonceSize = 16

	// discoEpoch is how often the demultiplexing tag rotates. A receiver holds
	// the tags for the previous, current and next epoch at once, so tag lookup
	// tolerates at least +-120s of clock skew -- deliberately wider than the
	// +-30s the header's timestamp tolerates, so that a skewed clock shows up as
	// a counted, diagnosable rejection rather than as packets that vanish before
	// anything can count them.
	//
	// "At least" because the tolerance depends on where in the epoch the
	// receiver stands: one whole epoch back and two forward from the start of
	// its own, so 120s is the worst case and 240s the best.
	// TestDiscoTagCoversTheEpochsAround pins both ends, at literal offsets from
	// a clock parked on an epoch boundary.
	discoEpoch = 120 * time.Second

	// discoEpochsHeld is the previous, current and next epoch.
	discoEpochsHeld = 3

	// discoMaxSkew is how far the header timestamp may sit from local time.
	discoMaxSkew = 30 * time.Second

	// DiscoMaxCandidates bounds a CALLME. A peer that has been compromised can
	// otherwise use one packet to point us at an arbitrary number of addresses.
	DiscoMaxCandidates = 16

	// discoSeqCeiling is the first sequence number a sender will not issue. Its
	// counter stops one below it and never advances again, so there is no value
	// of it from which a further send can wrap. At the cadence a selector probes
	// at the ceiling is several years away and unreachable in practice, but a
	// silent wrap would reopen the replay window and there is no reason to leave
	// that possible; see discoSession.nextSeq for how nearly it was left
	// possible anyway.
	discoSeqCeiling = 0xFFFFFFF0

	discoFamilyV4 byte = 0x04
	discoFamilyV6 byte = 0x06
)

var (
	// ErrNotDisco means the datagram is not addressed to any session we hold.
	// The demultiplexer must hand such a packet to QUIC, never drop it: the
	// tag is only eight bytes, so a real QUIC packet collides with a registered
	// tag once in 2^64, and dropping on collision would be a phantom packet
	// loss nobody could ever diagnose.
	ErrNotDisco = errors.New("not a disco packet")

	// ErrDiscoAuth is a tag that matched and an AEAD that did not. It is either
	// that same collision or a forgery, and neither can be told from the other,
	// so it is treated as ErrNotDisco is: the packet goes on to QUIC.
	ErrDiscoAuth = errors.New("disco authentication failed")

	ErrDiscoBadVersion     = errors.New("unknown disco version")
	ErrDiscoClockSkew      = errors.New("disco timestamp outside the accepted window")
	ErrInvalidDiscoPacket  = errors.New("invalid disco packet")
	ErrDiscoSecretTooShort = errors.New("disco secret must be at least 32 bytes")
)

// DiscoType is the packet type in the authenticated header.
type DiscoType byte

const (
	DiscoProbeType   DiscoType = 0x10
	DiscoPongType    DiscoType = 0x11
	DiscoCallMeType  DiscoType = 0x12
	DiscoBindType    DiscoType = 0x13
	DiscoBindAckType DiscoType = 0x14
)

func (t DiscoType) String() string {
	switch t {
	case DiscoProbeType:
		return "PROBE"
	case DiscoPongType:
		return "PONG"
	case DiscoCallMeType:
		return "CALLME"
	case DiscoBindType:
		return "BIND"
	case DiscoBindAckType:
		return "BINDACK"
	default:
		return "disco(0x" + strconv.FormatUint(uint64(t), 16) + ")"
	}
}

// DiscoHeader is the authenticated header, as decoded.
type DiscoHeader struct {
	Type DiscoType
	Seq  uint32
	TS   time.Time
}

// DiscoPacket is one disco packet. Exactly one payload field is set, and which
// one is decided by Header.Type.
type DiscoPacket struct {
	Header  DiscoHeader
	Probe   *DiscoProbe
	Pong    *DiscoPong
	CallMe  *DiscoCallMe
	Bind    *DiscoBind
	BindAck *DiscoBindAck
}

// DiscoProbe asks a candidate address whether it carries packets to the peer.
type DiscoProbe struct {
	Token    [8]byte
	TxMicros int64
}

// DiscoPong answers a probe, and reports the source address the responder saw.
//
// ObservedAddr is what lets the two ends act as each other's STUN server. It is
// not a convenience: once a server stops following source-address changes
// unconditionally, a NAT rebinding is only survivable if the client can discover
// its new mapping, and on a network where public STUN is blocked this is the
// only way it can.
type DiscoPong struct {
	Token        [8]byte
	TxMicrosEcho int64
	ObservedAddr netip.AddrPort
}

// DiscoCandidate is one address a peer offers in a CALLME.
type DiscoCandidate struct {
	Addr     netip.AddrPort
	Priority uint8
}

// DiscoCallMe offers the sender's current candidate addresses.
type DiscoCallMe struct{ Candidates []DiscoCandidate }

// DiscoBind claims a return path. The receiver must not act on the claim until
// it has answered with a BINDACK carrying the same nonce and seen the claim
// confirmed; see the design's three-step exchange.
type DiscoBind struct {
	Nonce       [DiscoBindNonceSize]byte
	ClaimedAddr netip.AddrPort
}

// DiscoBindAck echoes a BIND's nonce together with the address the responder
// actually observed, which is what makes the claim checkable rather than
// asserted.
type DiscoBindAck struct {
	Nonce        [DiscoBindNonceSize]byte
	ObservedAddr netip.AddrPort
}

// DiscoSkewError carries how far off the peer's clock looked, so that the
// operational counter can report a number an operator can act on instead of
// just a count of failures.
type DiscoSkewError struct{ Skew time.Duration }

func (e *DiscoSkewError) Error() string {
	return fmt.Sprintf("%s: peer clock is %s off", ErrDiscoClockSkew, e.Skew)
}

func (e *DiscoSkewError) Unwrap() error { return ErrDiscoClockSkew }

// DiscoKeys is one connection's disco key schedule.
//
// Both ends derive it independently from the same per-connection secret, so
// nothing about it travels on the wire, and neither the rendezvous server nor
// another user of the same deployment can reconstruct it. That is why the secret
// has to be the TLS exporter's output and not anything derived from the
// obfuscation password: the obfuscation password is deployment-wide, so a disco
// key derived from it would let every user of a deployment forge every other
// user's path claims, which is the exact attack the authentication exists to
// stop.
//
// A reconnect is a new TLS handshake and therefore a new secret. Anything keyed
// on these keys must be discarded when the connection is; migration within one
// connection keeps them.
type DiscoKeys struct {
	tagSend []byte
	tagRecv []byte
	seal    cipherAEAD
	open    cipherAEAD
	probe   []byte
}

// cipherAEAD is the subset of cipher.AEAD this file uses. It is named here so
// the struct above reads as what it is -- one direction sealing, the other
// opening -- rather than as two identical interface values.
type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// NewDiscoKeys derives the schedule from a per-connection secret.
//
// secret is the TLS exporter's output. server reverses the two directions, so
// that each end seals with the key the other opens with and a packet reflected
// back at its sender cannot authenticate.
func NewDiscoKeys(secret []byte, server bool) (*DiscoKeys, error) {
	if len(secret) < crypto.MinSecretLen {
		return nil, ErrDiscoSecretTooShort
	}
	tagC2S, err := crypto.DeriveFromSecret(secret, crypto.CtxDiscoTagC2S, discoKeyLen)
	if err != nil {
		return nil, err
	}
	tagS2C, err := crypto.DeriveFromSecret(secret, crypto.CtxDiscoTagS2C, discoKeyLen)
	if err != nil {
		return nil, err
	}
	bodyC2S, err := crypto.DeriveFromSecret(secret, crypto.CtxDiscoBodyC2S, discoKeyLen)
	if err != nil {
		return nil, err
	}
	bodyS2C, err := crypto.DeriveFromSecret(secret, crypto.CtxDiscoBodyS2C, discoKeyLen)
	if err != nil {
		return nil, err
	}
	probe, err := crypto.DeriveFromSecret(secret, crypto.CtxDiscoProbe, discoKeyLen)
	if err != nil {
		return nil, err
	}

	tagSend, tagRecv := tagC2S, tagS2C
	bodySend, bodyRecv := bodyC2S, bodyS2C
	if server {
		tagSend, tagRecv = tagS2C, tagC2S
		bodySend, bodyRecv = bodyS2C, bodyC2S
	}
	sealAEAD, err := chacha20poly1305.New(bodySend)
	if err != nil {
		return nil, err
	}
	openAEAD, err := chacha20poly1305.New(bodyRecv)
	if err != nil {
		return nil, err
	}
	return &DiscoKeys{
		tagSend: tagSend,
		tagRecv: tagRecv,
		seal:    sealAEAD,
		open:    openAEAD,
		probe:   probe,
	}, nil
}

// SendTag is the tag this end puts on packets sent at now.
func (k *DiscoKeys) SendTag(now time.Time) ([discoTagLen]byte, error) {
	return discoTag(k.tagSend, discoEpochOf(now))
}

// RecvTags are the tags a receiver must have registered at now: the previous,
// current and next epoch.
//
// Holding three rather than one is what keeps a clock difference between the two
// ends from making packets disappear. It is also why the tag table has to be
// rebuilt as epochs pass, rather than only when sessions come and go.
func (k *DiscoKeys) RecvTags(now time.Time) ([][discoTagLen]byte, error) {
	epoch := discoEpochOf(now)
	out := make([][discoTagLen]byte, 0, discoEpochsHeld)
	for _, e := range []uint64{epoch - 1, epoch, epoch + 1} {
		tag, err := discoTag(k.tagRecv, e)
		if err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	return out, nil
}

func discoEpochOf(now time.Time) uint64 {
	secs := now.Unix()
	if secs < 0 {
		secs = 0
	}
	return uint64(secs) / uint64(discoEpoch/time.Second)
}

func discoTag(tagKey []byte, epoch uint64) ([discoTagLen]byte, error) {
	var out [discoTagLen]byte
	b, err := crypto.DeriveFromSecret(tagKey, crypto.CtxDiscoEpoch+"/"+strconv.FormatUint(epoch, 10), discoTagLen)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// ProbeToken binds a probe to the candidate address it was sent to.
//
// A PONG carries the token back, and the prober recomputes it from the address
// the PONG *arrived from*. A PONG replayed or reflected from anywhere else
// computes a different token and is dropped, which is what lets the prober keep
// no table of probes in flight at all -- and so removes a memory the far end
// could otherwise grow by asking to be probed.
func ProbeToken(k *DiscoKeys, to netip.AddrPort, txMicros int64) [8]byte {
	mac := hmac.New(sha256.New, k.probe)
	addr := to.Addr().Unmap()
	b, _ := addr.MarshalBinary()
	_, _ = mac.Write(b)
	var scratch [10]byte
	binary.BigEndian.PutUint16(scratch[:2], to.Port())
	binary.BigEndian.PutUint64(scratch[2:], uint64(txMicros))
	_, _ = mac.Write(scratch[:])
	var out [8]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// CheckProbeToken reports whether token is the one this end would have signed
// for a probe sent to from at txMicros.
func CheckProbeToken(k *DiscoKeys, from netip.AddrPort, txMicros int64, token [8]byte) bool {
	want := ProbeToken(k, from, txMicros)
	return subtle.ConstantTimeCompare(want[:], token[:]) == 1
}

// EncodeDisco seals p as the seq'th packet this end sends.
//
// padTo is the exact wire length the packet takes, and it is a parameter rather
// than a constant because a constant is what the measurement rejected: padding
// every control packet to quic-go's InitialPacketSize of 1250 was caught at 100%
// by an offline-learned length whitelist, in both deployments and both
// directions, because path MTU discovery moves a real datagram to 1439 and an
// obfuscator adds its overhead on top, so 1250 lands in a length bucket that no
// data packet ever occupies. The caller must hand over a length this connection
// already sends at; DiscoPacketConn does.
//
// p.Header.Seq and p.Header.TS are what DecodeDisco fills in and are ignored
// here -- seq and now are the inputs.
func EncodeDisco(p DiscoPacket, k *DiscoKeys, seq uint32, now time.Time, padTo int) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: no keys", ErrInvalidDiscoPacket)
	}
	payload, err := appendDiscoPayload(nil, p)
	if err != nil {
		return nil, err
	}
	if padTo < discoMinWire || padTo > discoMaxWire {
		return nil, fmt.Errorf("%w: wire length %d out of range", ErrInvalidDiscoPacket, padTo)
	}
	plainLen := padTo - discoTagLen - discoNonceLen - discoSealLen
	if plainLen < discoHeaderLen+len(payload) {
		return nil, fmt.Errorf("%w: %d-byte payload does not fit in a %d-byte packet",
			ErrInvalidDiscoPacket, len(payload), padTo)
	}
	tag, err := k.SendTag(now)
	if err != nil {
		return nil, err
	}

	out := make([]byte, discoTagLen+discoNonceLen, padTo)
	copy(out, tag[:])
	if _, err := rand.Read(out[discoTagLen:]); err != nil {
		return nil, err
	}

	// The padding is zero rather than random. It is inside the AEAD, so no
	// observer ever sees it, and filling it from crypto/rand would cost the send
	// path a kilobyte of randomness per probe to hide bytes that are already
	// hidden.
	plain := make([]byte, plainLen)
	plain[0] = discoVersion
	plain[1] = byte(p.Header.Type)
	binary.BigEndian.PutUint16(plain[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint32(plain[4:8], uint32(now.Unix()))
	binary.BigEndian.PutUint32(plain[8:12], seq)
	copy(plain[discoHeaderLen:], payload)

	nonce := out[discoTagLen : discoTagLen+discoNonceLen]
	// The tag is the additional data, so a packet cannot be lifted out of one
	// session's tag and replayed under another's.
	return k.seal.Seal(out, nonce, plain, out[:discoTagLen]), nil
}

// DecodeDisco opens wire.
//
// It returns ErrNotDisco when the leading tag belongs to no epoch of this
// schedule and ErrDiscoAuth when the tag matched but the AEAD did not. The
// demultiplexer must treat both as "hand this datagram to QUIC" rather than as
// a failure, because both are what a QUIC packet that happens to collide with a
// registered tag looks like.
//
// Every check here is on data the caller already has: nothing about the packet
// is remembered, and the sequence number is returned rather than acted on, so
// that the one piece of state a disco packet can advance -- the replay window --
// is advanced in one place after every stateless check has passed.
func DecodeDisco(wire []byte, k *DiscoKeys, now time.Time) (DiscoPacket, error) {
	if k == nil {
		return DiscoPacket{}, ErrNotDisco
	}
	if len(wire) < discoMinWire || len(wire) > discoMaxWire {
		return DiscoPacket{}, ErrNotDisco
	}
	tags, err := k.RecvTags(now)
	if err != nil {
		return DiscoPacket{}, err
	}
	var wireTag [discoTagLen]byte
	copy(wireTag[:], wire)
	found := false
	for _, t := range tags {
		if t == wireTag {
			found = true
			break
		}
	}
	if !found {
		return DiscoPacket{}, ErrNotDisco
	}
	return decodeDiscoBody(wire, k, now)
}

// decodeDiscoBody is DecodeDisco with the tag lookup already done, which is what
// the demultiplexer needs: it finds the session by tag through one map lookup
// over every session at once, and must not then re-derive that session's tags.
func decodeDiscoBody(wire []byte, k *DiscoKeys, now time.Time) (DiscoPacket, error) {
	nonce := wire[discoTagLen : discoTagLen+discoNonceLen]
	plain, err := k.open.Open(nil, nonce, wire[discoTagLen+discoNonceLen:], wire[:discoTagLen])
	if err != nil {
		return DiscoPacket{}, ErrDiscoAuth
	}
	if len(plain) < discoHeaderLen {
		return DiscoPacket{}, fmt.Errorf("%w: header truncated", ErrInvalidDiscoPacket)
	}
	if plain[0] != discoVersion {
		return DiscoPacket{}, fmt.Errorf("%w: version 0x%02x", ErrDiscoBadVersion, plain[0])
	}
	payloadLen := int(binary.BigEndian.Uint16(plain[2:4]))
	if discoHeaderLen+payloadLen > len(plain) {
		return DiscoPacket{}, fmt.Errorf("%w: payload length %d exceeds packet", ErrInvalidDiscoPacket, payloadLen)
	}
	ts := time.Unix(int64(binary.BigEndian.Uint32(plain[4:8])), 0)
	if skew := now.Sub(ts); skew > discoMaxSkew || skew < -discoMaxSkew {
		return DiscoPacket{}, &DiscoSkewError{Skew: skew}
	}
	p := DiscoPacket{Header: DiscoHeader{
		Type: DiscoType(plain[1]),
		Seq:  binary.BigEndian.Uint32(plain[8:12]),
		TS:   ts,
	}}
	if p.Header.Seq == 0 {
		// Sequence numbers start at 1, so zero is either a sender that never
		// incremented or a forgery aimed at the bottom of the replay window.
		return DiscoPacket{}, fmt.Errorf("%w: sequence number zero", ErrInvalidDiscoPacket)
	}
	if err := parseDiscoPayload(&p, plain[discoHeaderLen:discoHeaderLen+payloadLen]); err != nil {
		return DiscoPacket{}, err
	}
	return p, nil
}

func appendDiscoPayload(dst []byte, p DiscoPacket) ([]byte, error) {
	switch p.Header.Type {
	case DiscoProbeType:
		if p.Probe == nil {
			return nil, fmt.Errorf("%w: PROBE without a payload", ErrInvalidDiscoPacket)
		}
		dst = append(dst, p.Probe.Token[:]...)
		return binary.BigEndian.AppendUint64(dst, uint64(p.Probe.TxMicros)), nil
	case DiscoPongType:
		if p.Pong == nil {
			return nil, fmt.Errorf("%w: PONG without a payload", ErrInvalidDiscoPacket)
		}
		dst = append(dst, p.Pong.Token[:]...)
		dst = binary.BigEndian.AppendUint64(dst, uint64(p.Pong.TxMicrosEcho))
		return appendDiscoAddrPort(dst, p.Pong.ObservedAddr)
	case DiscoCallMeType:
		if p.CallMe == nil {
			return nil, fmt.Errorf("%w: CALLME without a payload", ErrInvalidDiscoPacket)
		}
		if len(p.CallMe.Candidates) > DiscoMaxCandidates {
			return nil, fmt.Errorf("%w: %d candidates, at most %d",
				ErrInvalidDiscoPacket, len(p.CallMe.Candidates), DiscoMaxCandidates)
		}
		dst = append(dst, byte(len(p.CallMe.Candidates)))
		for _, c := range p.CallMe.Candidates {
			var err error
			if dst, err = appendDiscoAddrPort(dst, c.Addr); err != nil {
				return nil, err
			}
			dst = append(dst, c.Priority)
		}
		return dst, nil
	case DiscoBindType:
		if p.Bind == nil {
			return nil, fmt.Errorf("%w: BIND without a payload", ErrInvalidDiscoPacket)
		}
		dst = append(dst, p.Bind.Nonce[:]...)
		return appendDiscoAddrPort(dst, p.Bind.ClaimedAddr)
	case DiscoBindAckType:
		if p.BindAck == nil {
			return nil, fmt.Errorf("%w: BINDACK without a payload", ErrInvalidDiscoPacket)
		}
		dst = append(dst, p.BindAck.Nonce[:]...)
		return appendDiscoAddrPort(dst, p.BindAck.ObservedAddr)
	default:
		return nil, fmt.Errorf("%w: unknown type 0x%02x", ErrInvalidDiscoPacket, byte(p.Header.Type))
	}
}

func parseDiscoPayload(p *DiscoPacket, b []byte) error {
	switch p.Header.Type {
	case DiscoProbeType:
		if len(b) != 16 {
			return fmt.Errorf("%w: PROBE payload is %d bytes", ErrInvalidDiscoPacket, len(b))
		}
		probe := &DiscoProbe{TxMicros: int64(binary.BigEndian.Uint64(b[8:16]))}
		copy(probe.Token[:], b[:8])
		p.Probe = probe
		return nil
	case DiscoPongType:
		if len(b) < 16 {
			return fmt.Errorf("%w: PONG payload is %d bytes", ErrInvalidDiscoPacket, len(b))
		}
		pong := &DiscoPong{TxMicrosEcho: int64(binary.BigEndian.Uint64(b[8:16]))}
		copy(pong.Token[:], b[:8])
		addr, n, err := parseDiscoAddrPort(b[16:])
		if err != nil {
			return err
		}
		if 16+n != len(b) {
			return fmt.Errorf("%w: PONG payload has %d trailing bytes", ErrInvalidDiscoPacket, len(b)-16-n)
		}
		pong.ObservedAddr = addr
		p.Pong = pong
		return nil
	case DiscoCallMeType:
		if len(b) < 1 {
			return fmt.Errorf("%w: CALLME payload is empty", ErrInvalidDiscoPacket)
		}
		count := int(b[0])
		if count > DiscoMaxCandidates {
			return fmt.Errorf("%w: CALLME offers %d candidates, at most %d",
				ErrInvalidDiscoPacket, count, DiscoMaxCandidates)
		}
		callMe := &DiscoCallMe{}
		rest := b[1:]
		for i := 0; i < count; i++ {
			addr, n, err := parseDiscoAddrPort(rest)
			if err != nil {
				return err
			}
			rest = rest[n:]
			if len(rest) < 1 {
				return fmt.Errorf("%w: CALLME candidate %d has no priority", ErrInvalidDiscoPacket, i)
			}
			callMe.Candidates = append(callMe.Candidates, DiscoCandidate{Addr: addr, Priority: rest[0]})
			rest = rest[1:]
		}
		if len(rest) != 0 {
			return fmt.Errorf("%w: CALLME payload has %d trailing bytes", ErrInvalidDiscoPacket, len(rest))
		}
		p.CallMe = callMe
		return nil
	case DiscoBindType:
		bind := &DiscoBind{}
		addr, err := parseDiscoNonceAndAddr(b, bind.Nonce[:], "BIND")
		if err != nil {
			return err
		}
		bind.ClaimedAddr = addr
		p.Bind = bind
		return nil
	case DiscoBindAckType:
		ack := &DiscoBindAck{}
		addr, err := parseDiscoNonceAndAddr(b, ack.Nonce[:], "BINDACK")
		if err != nil {
			return err
		}
		ack.ObservedAddr = addr
		p.BindAck = ack
		return nil
	default:
		return fmt.Errorf("%w: unknown type 0x%02x", ErrInvalidDiscoPacket, byte(p.Header.Type))
	}
}

func parseDiscoNonceAndAddr(b, nonce []byte, name string) (netip.AddrPort, error) {
	if len(b) < DiscoBindNonceSize {
		return netip.AddrPort{}, fmt.Errorf("%w: %s payload is %d bytes", ErrInvalidDiscoPacket, name, len(b))
	}
	copy(nonce, b[:DiscoBindNonceSize])
	addr, n, err := parseDiscoAddrPort(b[DiscoBindNonceSize:])
	if err != nil {
		return netip.AddrPort{}, err
	}
	if DiscoBindNonceSize+n != len(b) {
		return netip.AddrPort{}, fmt.Errorf("%w: %s payload has %d trailing bytes",
			ErrInvalidDiscoPacket, name, len(b)-DiscoBindNonceSize-n)
	}
	return addr, nil
}

// appendDiscoAddrPort writes family(1) ‖ addr(4|16) ‖ port(2).
//
// Addresses are unmapped first, matching what addrToAddrPort does to every
// address this package reads off a socket. What that buys is one encoding per
// peer: without it the same IPv4 peer goes out as 7 bytes or as 19 depending on
// whether the kernel handed it back through a v4 or a dual-stack socket.
//
// An earlier version of this comment claimed the two forms would then not
// compare equal at the far end. They would -- parseDiscoAddrPort unmaps what it
// reads, so the round trip is intact either way, and removing the Unmap here
// left every test passing. The consequence that is real is the size: a CALLME
// offering the maximum sixteen candidates is 129 bytes one way and 321 the
// other, so whether it fits the packet would start to depend on the peer's
// socket family. TestDiscoEncodesMappedV4AsV4 pins the encoding.
func appendDiscoAddrPort(dst []byte, a netip.AddrPort) ([]byte, error) {
	addr := a.Addr().Unmap()
	switch {
	case addr.Is4():
		b := addr.As4()
		dst = append(dst, discoFamilyV4)
		dst = append(dst, b[:]...)
	case addr.Is6():
		b := addr.As16()
		dst = append(dst, discoFamilyV6)
		dst = append(dst, b[:]...)
	default:
		return nil, fmt.Errorf("%w: address %q is neither v4 nor v6", ErrInvalidDiscoPacket, a)
	}
	return binary.BigEndian.AppendUint16(dst, a.Port()), nil
}

// parseDiscoAddrPort reads one encoded address and reports how many bytes it
// consumed.
func parseDiscoAddrPort(b []byte) (netip.AddrPort, int, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: address family is missing", ErrInvalidDiscoPacket)
	}
	var size int
	switch b[0] {
	case discoFamilyV4:
		size = 4
	case discoFamilyV6:
		size = 16
	default:
		return netip.AddrPort{}, 0, fmt.Errorf("%w: unknown address family 0x%02x", ErrInvalidDiscoPacket, b[0])
	}
	n := 1 + size + 2
	if len(b) < n {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: address truncated", ErrInvalidDiscoPacket)
	}
	addr, ok := netip.AddrFromSlice(b[1 : 1+size])
	if !ok {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: unparsable address", ErrInvalidDiscoPacket)
	}
	port := binary.BigEndian.Uint16(b[1+size : n])
	return netip.AddrPortFrom(addr.Unmap(), port), n, nil
}
