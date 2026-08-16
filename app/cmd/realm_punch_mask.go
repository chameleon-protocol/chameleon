package cmd

import (
	"errors"
	"strings"

	"github.com/chameleon-protocol/chameleon/extras/v2/realm"
)

// errRealmPunchNeedsObfs is a startup failure, not a downgrade. Punch packets
// share a five-tuple with the QUIC connection, and under obfs.type plain there
// is no envelope that hides in that flow: the best measured candidate still
// showed 50% detection client-to-server and 24% server-to-client. A realm
// listener that came up anyway would be handing the operator a connection that
// works and is trivially fingerprinted, which is worse than one that refuses to
// start.
var errRealmPunchNeedsObfs = errors.New(
	"realm punching requires obfs.type salamander-v2, so the punch mask key has a password " +
		"to derive from and the punch packets have a measured background to hide in")

// errRealmPunchNeedsV2 is the same refusal for the obfuscators that do have a
// password but whose traffic nobody has measured.
//
// Punching hides by looking like the obfuscated flow beside it, and what that
// flow looks like was captured for salamander v2 only. Salamander v1 and gecko
// were once accepted on the argument that their output is not clear QUIC
// either -- but that is an argument, and the whole envelope was redesigned
// because an argument of exactly that shape turned out to be wrong when it was
// finally measured. Gecko additionally pads every datagram to a random size in
// a range, so there is no modal length for a punch packet to copy and it would
// fall back to a band that measures 85-97%.
var errRealmPunchNeedsV2 = errors.New(
	"realm punching requires obfs.type salamander-v2: it is the only obfuscator whose traffic " +
		"the punch packet lengths were measured against")

// realmPunchMask derives the realm-wide key that masks punch packets, from the
// obfuscation password of whichever obfuscator is configured.
//
// The obfs password is the only secret both ends already share that the
// rendezvous server does not hold, which is what the mask needs: the rendezvous
// relays punch metadata verbatim, so anything derived from that metadata is a
// key the relay also has.
//
// Only salamander v2 carries a realm, so v1 and gecko derive with an empty one.
// That means two deployments picking the same v1 password share a punch mask —
// exactly the weakness those obfuscators already have at their own layer, so
// punching does not add one. They are accepted rather than rejected because
// their output is not clear QUIC either; that is an argument, not a
// measurement, and the measurement covers salamander v2 only.
func realmPunchMask(obfsType, salamanderV2Password, salamanderV2Realm string) (realm.PunchMask, error) {
	// Matched exactly as wrapObfs dispatches, so the key exists when — and only
	// when — an obfuscator actually engages.
	switch strings.ToLower(obfsType) {
	case "", "plain":
		return realm.PunchMask{}, configError{Field: "obfs.type", Err: errRealmPunchNeedsObfs}
	case "salamander", "gecko":
		return realm.PunchMask{}, configError{Field: "obfs.type", Err: errRealmPunchNeedsV2}
	case "salamander-v2":
		return punchMaskOrConfigError("obfs.salamanderV2.password", salamanderV2Password, salamanderV2Realm)
	default:
		return realm.PunchMask{}, configError{Field: "obfs.type", Err: errors.New("unsupported obfuscation type")}
	}
}

func punchMaskOrConfigError(field, password, realmName string) (realm.PunchMask, error) {
	mask, err := realm.NewPunchMask([]byte(password), realmName)
	if err != nil {
		return realm.PunchMask{}, configError{Field: field, Err: err}
	}
	return mask, nil
}
