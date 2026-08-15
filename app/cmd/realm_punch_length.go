package cmd

import (
	"net"
	"strings"

	"github.com/chameleon-protocol/chameleon/extras/v2/obfs"
)

// An initiator punches on a bare socket: the QUIC connection does not exist
// yet, so nothing has gone out that a punch packet could copy a length from.
//
// What it pads to instead is the length the connection will spend most of its
// life sending. That is not the Initial, which was the obvious guess and is
// wrong: an Initial goes out once or twice per connection, so a length
// classifier trained on real traffic has never seen it often enough to
// whitelist it, and hundreds of punch packets at that length are both novel and
// alone in their own length bucket -- which is the condition that makes the
// probe cadence visible. Measured, padding to the Initial scores 0% one way and
// 100% the other, against 0% both ways for the modal length.
//
// The modal length is the full datagram after path MTU discovery has settled,
// which is about 60% of everything a loaded connection sends.
//
// The number is quic-go's behaviour rather than a constant it exports, so it is
// measured here and pinned by TestPunchWireLenMatchesTheModalDatagram, which
// runs a real connection and takes the mode. A value that misses is worse than
// no value: the whole point is to land in the biggest bucket on the path.
const (
	// What a quic-go connection settles on for a full datagram on a 1500-byte
	// path, measured. Not derived from the MTU: quic-go's own ceiling and its
	// probe schedule decide where it stops, and 1500 - 20 - 8 is not where.
	//
	// The two directions differ by two bytes and each side has to use its own:
	// a responder padding to the client's modal length is padding to a length
	// its own direction does not have as its mode.
	quicFullDatagramSize       = 1439
	quicFullDatagramSizeServer = 1441
)

// realmPunchWireLen returns the wire length this client's connection will
// mostly send at, or zero when it cannot be worked out.
//
// Zero is a normal answer, not a failure: gecko pads every datagram to a random
// size in a configured range, so there is no single length to match, and a
// caller that cannot name the length is better off with the fallback band than
// with a confident wrong number.
func realmPunchWireLen(obfsType string, probe net.PacketConn) int {
	return punchWireLen(obfsType, probe, quicFullDatagramSize)
}

// realmPunchWireLenServer is the same for a responder, whose modal datagram is
// two bytes longer than a client's.
func realmPunchWireLenServer(obfsType string, probe net.PacketConn) int {
	return punchWireLen(obfsType, probe, quicFullDatagramSizeServer)
}

func punchWireLen(obfsType string, probe net.PacketConn, fullDatagram int) int {
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
	return fullDatagram + overhead
}
