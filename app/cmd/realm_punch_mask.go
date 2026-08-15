package cmd

import (
	"errors"
	"strings"

	"github.com/chameleon-protocol/chameleon/extras/v2/realm"
)

// errRealmPunchNeedsObfs is a startup failure, not a downgrade. Punch packets
// share a five-tuple with the QUIC connection, and under obfs.type plain there
// is no envelope that hides in that flow: the best measured candidate still
// showed 50% detection client-to-server and 24% server-to-client
// (tests/spike/discofp, docs/design/p1-punch-envelope.md). A realm listener
// that came up anyway would be handing the operator a connection that works and
// is trivially fingerprinted, which is worse than one that refuses to start.
var errRealmPunchNeedsObfs = errors.New(
	"realm punching requires obfuscation: set obfs.type (salamander-v2 is the one whose " +
		"background this was measured against) so the punch mask key has a password to derive from")

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
func realmPunchMask(obfsType, salamanderPassword, salamanderV2Password, salamanderV2Realm, geckoPassword string) (realm.PunchMask, error) {
	// Matched exactly as wrapObfs dispatches, so the key exists when — and only
	// when — an obfuscator actually engages.
	switch strings.ToLower(obfsType) {
	case "", "plain":
		return realm.PunchMask{}, configError{Field: "obfs.type", Err: errRealmPunchNeedsObfs}
	case "salamander":
		return punchMaskOrConfigError("obfs.salamander.password", salamanderPassword, "")
	case "salamander-v2":
		return punchMaskOrConfigError("obfs.salamanderV2.password", salamanderV2Password, salamanderV2Realm)
	case "gecko":
		return punchMaskOrConfigError("obfs.gecko.password", geckoPassword, "")
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
