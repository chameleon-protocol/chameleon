// Package crypto is the only place in chameleon that turns a user's password
// into key material. Nothing else may call argon2, hkdf, or a bare hash over
// the password: a derivation written inline is a derivation nobody reviews, and
// two call sites that hash the same password without domain separation share a
// key without anyone noticing.
package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Derivation contexts. One constant per use, each carrying a version number.
//
// These strings are protocol constants. Changing one changes the keys on both
// ends, so a change is a wire break and must come with a version bump in the
// name — never an edit in place.
const (
	CtxSalamanderV2Root = "chameleon/obfs/salamander-v2/root"
	CtxSalamanderV2C2S  = "chameleon/obfs/salamander-v2/c2s"
	CtxSalamanderV2S2C  = "chameleon/obfs/salamander-v2/s2c"
	CtxAppPadding       = "chameleon/protocol/padding-v1"
	CtxPunchMask        = "chameleon/punch-mask-v1"
)

// Argon2id parameters for password stretching.
//
// These are protocol constants, not tunables: the two ends derive keys
// independently with no handshake to negotiate over, so a mismatch is a silent
// failure to connect. Changing them means a new protocol version.
//
// The memory cost is well below RFC 9106's recommendation because the target
// hardware includes routers with 32-64 MB of RAM total, where allocating 64 MiB
// is not slow but fatal. Time cost compensates.
//
// Measured at 28 ms on an arm64 laptop core. golang.org/x/crypto/argon2 ships
// assembly for amd64 only, so that figure already reflects the pure-Go path
// that MIPS and ARMv7 routers will also take; scaled by clock and IPC they land
// somewhere in the low hundreds of milliseconds. Paid once per process, and the
// cache below keeps reconnects from paying it again.
//
// Still to check on real hardware before the first release, because these
// cannot change afterwards without a version bump: whether allocating 16 MiB is
// survivable on a 32 MB router, which is a question about the allocation, not
// about the time.
const (
	argon2Time    = 3
	argon2MemoryK = 16 * 1024 // 16 MiB
	argon2Threads = 1
	rootKeyLen    = 32
)

// MinPasswordLen is enforced here rather than at each call site so that no
// derivation can be reached with a trivially guessable input.
const MinPasswordLen = 4

var ErrPasswordTooShort = errors.New("password must be at least 4 bytes")

// RootKey is the output of password stretching. Subkeys are expanded from it.
type RootKey [rootKeyLen]byte

type rootKeyCacheKey struct {
	passwordHash [sha256.Size]byte
	realm        string
}

var rootKeyCache sync.Map // rootKeyCacheKey -> RootKey

// StretchPassword turns a user-typed password into a root key.
//
// The result is cached. That is not an optimization: the client rebuilds its
// config on every reconnect, so wrapping a connection re-enters this function
// on every port hop and every recovery. An uncached Argon2id would put a
// multi-second stall on the reconnect path of exactly the low-powered devices
// the memory cost was lowered for.
//
// realm scopes the derivation to one deployment. Two deployments that pick the
// same password but different realms get unrelated keys, which is what stops a
// single precomputed table from covering every chameleon deployment on earth.
// It is optional and defaults to empty; both ends must configure it the same.
func StretchPassword(password []byte, realm string) (RootKey, error) {
	if len(password) < MinPasswordLen {
		return RootKey{}, ErrPasswordTooShort
	}
	ck := rootKeyCacheKey{passwordHash: sha256.Sum256(password), realm: realm}
	if v, ok := rootKeyCache.Load(ck); ok {
		return v.(RootKey), nil
	}

	// The Argon2 salt is derived from a protocol constant rather than being
	// random, because there is no handshake: both ends must arrive at the same
	// key knowing only the password. That is the cost of a zero-round-trip
	// obfuscation layer, and it is why realm exists.
	saltInput := sha256.Sum256([]byte(CtxSalamanderV2Root + "\x00" + realm))
	key := argon2.IDKey(password, saltInput[:16], argon2Time, argon2MemoryK, argon2Threads, rootKeyLen)

	var rk RootKey
	copy(rk[:], key)
	rootKeyCache.Store(ck, rk)
	return rk, nil
}

// DeriveSubkey expands a root key into key material for one specific use.
// ctx must be one of the Ctx constants above.
func DeriveSubkey(root RootKey, ctx string, length int) ([]byte, error) {
	return hkdf.Expand(sha256.New, root[:], ctx, length)
}
