package cmd

import (
	"net"
	"strings"

	"github.com/chameleon-protocol/chameleon/extras/v2/obfs"
)

// An initiator punches on a bare socket: the QUIC connection does not exist
// yet, so nothing has gone out that a punch packet could copy a length from.
// What it does know is the length of the datagram it is about to send, because
// a QUIC Initial is padded to a fixed size and the obfuscator adds a fixed
// number of bytes on top. Punching at that length makes the punch packets the
// same size as the handshake that immediately follows them, instead of a size
// that appears nowhere else on the path.
//
// The two sizes are quic-go's, and they are not exported, so they are written
// out here and pinned by TestPunchInitialWireLenMatchesTheRealHandshake, which
// dials a real server and measures the first datagram. A wrong constant here
// would be worse than no constant at all: the whole point is to match, and a
// value that misses by one byte is a length nothing else on the path produces.
const (
	// quic-go internal/protocol.InitialPacketSize.
	quicInitialPacketSize = 1280
	// quic-go chrome_parrot.go chromeInitialPacketSize. Chrome sends a smaller
	// Initial than the quic-go default, and the parrot is on unless disabled.
	quicChromeInitialPacketSize = 1250
)

// realmPunchInitialWireLen returns the wire length of the first datagram this
// client will send, or zero when it cannot be worked out.
//
// Zero is a normal answer, not a failure: gecko pads every datagram to a random
// size in a configured range, so there is no single length to match, and a
// caller that cannot name the length is better off with the fallback band than
// with a confident wrong number.
func realmPunchInitialWireLen(obfsType string, disableChromeParrot bool, probe net.PacketConn) int {
	overhead, ok := obfs.WireOverheadOf(probe)
	if !ok {
		return 0
	}
	// Matched as wrapObfs dispatches: an obfuscator that pads to a range has no
	// fixed overhead to report, and WireOverheadOf already refuses it. This
	// switch exists so a new obfuscator has to be considered here rather than
	// silently inheriting whatever its overhead happens to be.
	switch strings.ToLower(obfsType) {
	case "salamander", "salamander-v2":
	default:
		return 0
	}
	if disableChromeParrot {
		return quicInitialPacketSize + overhead
	}
	return quicChromeInitialPacketSize + overhead
}
