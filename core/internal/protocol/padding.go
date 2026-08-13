package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

const (
	paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// padding specifies a half-open range [Min, Max).
type padding struct {
	Min int
	Max int
}

// generate returns a fresh padding string. It is deliberately not named
// String: a Stringer that returns random data of kilobyte size is a trap for
// anything that formats the value.
func (p padding) generate() string {
	n := p.Min
	if span := p.Max - p.Min; span > 0 {
		n += int(randUint32() % uint32(span))
	}
	bs := make([]byte, n)
	// crypto/rand.Read never returns an error, it panics if the system
	// source is unusable, so there is nothing to handle here.
	_, _ = rand.Read(bs)
	for i, b := range bs {
		bs[i] = paddingChars[int(b)%len(paddingChars)]
	}
	return string(bs)
}

// PaddingScheme holds the length distribution of every padding field of the
// protocol. The distribution used to be a compile-time constant, which means
// every deployment in the world produced auth requests and TCP request frames
// with the exact same length distribution - a classifier only needs to collect
// lengths, no keys or content involved. Deriving the ranges from a deployment
// secret makes that feature deployment-specific instead of global.
type PaddingScheme struct {
	AuthRequest  padding
	AuthResponse padding
	TCPRequest   padding
	TCPResponse  padding
}

// defaultPaddingScheme is the upstream distribution. It stays the fallback so
// that a peer without a padding seed keeps behaving exactly as before.
var defaultPaddingScheme = PaddingScheme{
	AuthRequest:  padding{Min: 256, Max: 2048},
	AuthResponse: padding{Min: 256, Max: 2048},
	TCPRequest:   padding{Min: 64, Max: 512},
	TCPResponse:  padding{Min: 128, Max: 1024},
}

// paddingBounds is the space a derived range is drawn from: Min comes from
// [MinLo, MinHi) and the width of the range from [SpanLo, SpanHi). The bounds
// are picked so that the widest derived range still stays comfortably below
// MaxPaddingLength, and so that two seeds have a decent chance of producing
// ranges that don't even overlap.
type paddingBounds struct {
	MinLo, MinHi   int
	SpanLo, SpanHi int
}

var (
	authPaddingBounds        = paddingBounds{MinLo: 64, MinHi: 1024, SpanLo: 256, SpanHi: 1536}
	tcpRequestPaddingBounds  = paddingBounds{MinLo: 16, MinHi: 256, SpanLo: 64, SpanHi: 768}
	tcpResponsePaddingBounds = paddingBounds{MinLo: 32, MinHi: 512, SpanLo: 128, SpanHi: 1024}
)

// NewPaddingScheme derives a scheme from seed, which is expected to be a key
// derived from the deployment secret (see extras/crypto, context "app-padding";
// core cannot derive it itself as it must not depend on extras). An empty seed
// yields the upstream scheme.
//
// The seed does not have to match between the two peers: padding is skipped by
// the reader, so a seeded peer and an unseeded one still interoperate. Using the
// same seed on both sides is merely what makes a deployment look consistent.
func NewPaddingScheme(seed []byte) *PaddingScheme {
	if len(seed) == 0 {
		s := defaultPaddingScheme
		return &s
	}
	return &PaddingScheme{
		AuthRequest:  derivePadding(seed, "auth-request", authPaddingBounds),
		AuthResponse: derivePadding(seed, "auth-response", authPaddingBounds),
		TCPRequest:   derivePadding(seed, "tcp-request", tcpRequestPaddingBounds),
		TCPResponse:  derivePadding(seed, "tcp-response", tcpResponsePaddingBounds),
	}
}

func derivePadding(seed []byte, label string, b paddingBounds) padding {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(label))
	sum := mac.Sum(nil)
	lo := b.MinLo + int(binary.BigEndian.Uint32(sum[0:4])%uint32(b.MinHi-b.MinLo))
	span := b.SpanLo + int(binary.BigEndian.Uint32(sum[4:8])%uint32(b.SpanHi-b.SpanLo))
	return padding{Min: lo, Max: lo + span}
}

// orDefault keeps a nil scheme usable, so that callers that have no
// configuration to pass (tests, tools) get the upstream behavior.
func (ps *PaddingScheme) orDefault() *PaddingScheme {
	if ps == nil {
		return &defaultPaddingScheme
	}
	return ps
}

func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
