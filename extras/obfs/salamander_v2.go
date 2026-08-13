// chameleon -- a censorship-resistant transport
// Copyright (C) 2026 The chameleon authors
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 3 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/chameleon-protocol/chameleon/extras/v2/crypto"
)

// Salamander v2 replaces v1's XOR obfuscation. v1 had three problems, and each
// one alone would justify this:
//
//   - It authenticated nothing. Deobfuscate returned success for any input of
//     at least 9 bytes. Replaying a recorded client Initial verbatim made the
//     server answer, which is an oracle: one recorded packet plus one replay
//     tells a censor it has found a chameleon server.
//   - Its keystream was a 32-byte pad repeated across the whole packet, so
//     c[i]^c[i+32] == p[i]^p[i+32] handed an observer plaintext differentials
//     with no key at all, against a QUIC long header whose leading bytes are
//     largely predictable.
//   - Its salt came from math/rand seeded with the wall clock.
//
// v2 is ChaCha20-Poly1305 over the whole datagram with a random 12-byte salt
// that doubles as the nonce, plus a timestamp and a replay set so a recorded
// packet cannot be made to produce a response twice.
//
// There is deliberately no version byte or magic number on the wire. Any
// plaintext constant is a fingerprint; v2 identifies itself by decrypting, and
// the chance of mistaking someone else's packet for ours is 2^-128.

const (
	smV2SaltLen = chacha20poly1305.NonceSize // 12, and it is the nonce
	smV2TSLen   = 4
	smV2TagLen  = chacha20poly1305.Overhead // 16
	smV2KeyLen  = chacha20poly1305.KeySize  // 32

	// Overhead is what v2 costs on the wire, against v1's 8 bytes. It comes out
	// of the path MTU: with path MTU discovery converging under the 1452-byte
	// ceiling quic-go imposes, usable datagrams drop by about 12 bytes on IPv4,
	// which is roughly 1.4% of goodput.
	//
	// The CPU cost is the larger one and should not be understated: on the send
	// path, 1400-byte packets went from 653 ns to 1581 ns single-threaded on
	// arm64. golang.org/x/crypto/chacha20poly1305 ships assembly for amd64
	// only, so that figure is the pure-Go path -- the same one MIPS and ARMv7
	// routers take, and amd64 servers do considerably better. In production the
	// packet also costs a syscall of 1-2 us, which this sits alongside rather
	// than replaces.
	//
	// ChaCha20-Poly1305 rather than AES-GCM because the target hardware
	// includes Raspberry Pis and routers without ARMv8 crypto extensions, where
	// AES in software is worse than this. The cipher is fixed by the protocol,
	// so it cannot be chosen per host.
	smV2Overhead = smV2SaltLen + smV2TSLen + smV2TagLen // 32

	// smV2MinLen is the shortest input that could possibly be ours: one byte of
	// payload plus the overhead. Anything shorter is dropped before doing any
	// cryptography, so garbage costs a length comparison and nothing more.
	smV2MinLen = smV2Overhead + 1

	// smV2MaxSkew is how far apart the two clocks may be. It bounds how long a
	// recorded packet stays replayable, which is what sets the retention the
	// replay set has to provide.
	smV2MaxSkew = 30 * time.Second
)

var ErrPasswordRequired = errors.New("obfs: password is required")

// Role picks which direction's key this end sends with. The two directions use
// different keys so that a packet cannot be reflected: bouncing a server's
// packet back at the server, or at another client, fails to authenticate. v1
// protected both directions with one keystream and had no such property.
type Role int

const (
	RoleClient Role = iota
	RoleServer
)

var _ obfuscator = (*salamanderV2)(nil)

// clock is injectable so tests can drive the timestamp window without sleeping.
type clock func() time.Time

type salamanderV2 struct {
	sendAEAD, recvAEAD aeadSealOpener
	now                clock

	// bootTime closes a hole that would otherwise reopen the oracle v2 exists
	// to shut. The replay set lives in memory, so a restart empties it while
	// the timestamp window still accepts anything from the last 30 seconds --
	// and restarts are frequent and can be induced. Until the process has been
	// up longer than the skew allowance, refuse timestamps from before it
	// started, which is the same thing as saying the replay set covers all of
	// history before boot.
	bootTime time.Time

	replay *replaySet

	stats *Stats
}

// aeadSealOpener is the subset of cipher.AEAD used here, named so the intent is
// visible at the call sites.
type aeadSealOpener interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// NewSalamanderV2 builds the obfuscator for one end of a connection.
//
// realm is optional and scopes key derivation to one deployment; both ends must
// set it identically. See crypto.StretchPassword for why it exists.
func NewSalamanderV2(password []byte, realm string, role Role) (*salamanderV2, error) {
	if len(password) == 0 {
		return nil, ErrPasswordRequired
	}
	root, err := crypto.StretchPassword(password, realm)
	if err != nil {
		return nil, err
	}
	c2s, err := crypto.DeriveSubkey(root, crypto.CtxSalamanderV2C2S, smV2KeyLen)
	if err != nil {
		return nil, err
	}
	s2c, err := crypto.DeriveSubkey(root, crypto.CtxSalamanderV2S2C, smV2KeyLen)
	if err != nil {
		return nil, err
	}
	sendKey, recvKey := c2s, s2c
	if role == RoleServer {
		sendKey, recvKey = s2c, c2s
	}
	sendAEAD, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}
	now := time.Now
	return &salamanderV2{
		sendAEAD: sendAEAD,
		recvAEAD: recvAEAD,
		now:      now,
		bootTime: now(),
		replay:   newReplaySet(),
		stats:    &Stats{},
	}, nil
}

// WrapPacketConnSalamanderV2 enables Salamander v2 on a PacketConn.
func WrapPacketConnSalamanderV2(conn net.PacketConn, password []byte, realm string, role Role) (net.PacketConn, error) {
	ob, err := NewSalamanderV2(password, realm, role)
	if err != nil {
		return nil, err
	}
	return wrapPacketConn(conn, ob), nil
}

// Obfuscate lays out [salt][seal(payload || timestamp)][tag].
//
// The timestamp is inside the ciphertext, not in front of it. A plaintext
// counter that ticks once per second at a fixed offset is a zero-false-positive
// signature for anyone watching the flow; encrypted, it is indistinguishable
// from the rest.
func (o *salamanderV2) Obfuscate(in, out []byte) int {
	if len(in) == 0 || len(out) < len(in)+smV2Overhead {
		return 0
	}
	salt := out[:smV2SaltLen]
	if _, err := rand.Read(salt); err != nil {
		return 0
	}
	// Assemble the plaintext where the ciphertext will go, then seal in place.
	n := copy(out[smV2SaltLen:], in)
	binary.BigEndian.PutUint32(out[smV2SaltLen+n:], uint32(o.now().Unix()))
	plaintext := out[smV2SaltLen : smV2SaltLen+n+smV2TSLen]
	o.sendAEAD.Seal(plaintext[:0], salt, plaintext, nil)
	return smV2SaltLen + n + smV2TSLen + smV2TagLen
}

// Deobfuscate returns 0 for anything that is not a packet we sent: wrong key,
// tampered, outside the clock window, or already seen. The caller cannot tell
// these apart, and neither can a prober -- every one of them produces exactly
// no response, which is the entire point.
//
// It may modify in, which holds the scratch buffer the caller read into.
//
// The four rejection causes are counted separately even though they are
// indistinguishable on the wire. An operator staring at a link that carries no
// traffic needs to know which one it is: a wrong password, a wrong clock and a
// prober replaying packets all look identical from here otherwise.
func (o *salamanderV2) Deobfuscate(in, out []byte) int {
	if len(in) < smV2MinLen {
		o.stats.Malformed.Add(1)
		return 0
	}
	salt := in[:smV2SaltLen]
	plaintext, err := o.recvAEAD.Open(in[smV2SaltLen:smV2SaltLen], salt, in[smV2SaltLen:], nil)
	if err != nil {
		o.stats.AEADFailed.Add(1)
		return 0
	}
	if len(plaintext) < smV2TSLen+1 {
		o.stats.Malformed.Add(1)
		return 0
	}
	payload := plaintext[:len(plaintext)-smV2TSLen]
	ts := int64(binary.BigEndian.Uint32(plaintext[len(plaintext)-smV2TSLen:]))

	now := o.now()
	if !o.timestampInWindow(ts, now) {
		// This packet authenticated, so the peer is genuine and the password is
		// right; only the clocks disagree. Record by how much, since that is
		// what turns the counter into an instruction.
		o.stats.recordSkew(ts, now.Unix())
		return 0
	}
	var key [smV2SaltLen]byte
	copy(key[:], salt)
	if o.replay.seenOrAdd(key, now) {
		o.stats.Replayed.Add(1)
		return 0
	}
	if len(out) < len(payload) {
		o.stats.Malformed.Add(1)
		return 0
	}
	return copy(out, payload)
}

func (o *salamanderV2) timestampInWindow(ts int64, now time.Time) bool {
	skew := int64(smV2MaxSkew / time.Second)
	if ts > now.Unix()+skew {
		return false
	}
	lower := now.Unix() - skew
	// The boot barrier, lifted once the process has been up long enough for the
	// replay set to cover the whole window on its own.
	if now.Sub(o.bootTime) < smV2MaxSkew {
		if b := o.bootTime.Unix(); b > lower {
			lower = b
		}
	}
	return ts >= lower
}

// Stats returns the rejection counters, broken down by cause. Every path out
// of Deobfuscate that returns 0 bumps exactly one of them.
func (o *salamanderV2) Stats() *Stats {
	return o.stats
}

// replaySet remembers which salts have been seen, exactly. A probabilistic
// structure is the wrong tool twice over: a false positive drops a legitimate
// packet, and worse, eviction is itself an attack -- spray enough forged
// entries and the real ones fall out, making the replay work again.
//
// Buckets rotate rather than being cleared, so retention is between three and
// four periods. Two buckets on a 60-second period would give exactly the 60
// seconds required and no margin at all for rotation lag or clock granularity.
type replaySet struct {
	mu         sync.Mutex
	buckets    [4]map[[smV2SaltLen]byte]struct{}
	idx        int
	lastRotate time.Time
}

const replayPeriod = smV2MaxSkew // 30s per bucket, 90-120s retained

func newReplaySet() *replaySet {
	r := &replaySet{}
	for i := range r.buckets {
		r.buckets[i] = make(map[[smV2SaltLen]byte]struct{})
	}
	return r
}

// seenOrAdd reports whether salt has been seen, recording it if not.
func (r *replaySet) seenOrAdd(salt [smV2SaltLen]byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastRotate.IsZero() {
		r.lastRotate = now
	}
	for now.Sub(r.lastRotate) >= replayPeriod {
		r.idx = (r.idx + 1) % len(r.buckets)
		clear(r.buckets[r.idx])
		r.lastRotate = r.lastRotate.Add(replayPeriod)
	}
	for i := range r.buckets {
		if _, ok := r.buckets[i][salt]; ok {
			return true
		}
	}
	r.buckets[r.idx][salt] = struct{}{}
	return false
}
