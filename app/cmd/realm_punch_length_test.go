package cmd

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/extras/v2/obfs"
)

// TestPunchWireLenIsTheModalDatagram pins the length a punch packet is padded
// to, and pins it as a number rather than as the arithmetic that produced it.
//
// 1471 is not a derivation. It is the modal wire length of a real client under
// salamander v2, taken from a packet capture of a loaded connection, where it
// was 60% of everything the client sent. Padding to it is the whole mechanism:
// a punch packet in the biggest bucket on the path is neither a novel length
// nor alone in a bucket where its own send cadence would show. Writing the
// arithmetic here instead would assert nothing, because the arithmetic is what
// is under test.
//
// If this fails, the constant has to be re-measured against a capture, not
// nudged until the test passes. A punch packet one bucket over is worse than
// one drawn from the fallback band.
func TestPunchWireLenIsTheModalDatagram(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer udp.Close()

	v2, err := obfs.WrapPacketConnSalamanderV2(udp, []byte("punch-length"), "deployment", obfs.RoleClient)
	require.NoError(t, err)
	assert.Equal(t, 1471, realmPunchWireLen("salamander-v2", v2))

	// Gecko pads every datagram to a random size in a range, so it has no modal
	// length to aim at and no fixed overhead to add. So does a socket with no
	// obfuscator at all. Both get the fallback band, which is the honest answer
	// when no length can be named.
	gecko, err := obfs.WrapPacketConnGecko(udp, obfs.GeckoOptions{Password: []byte("gecko-password")})
	require.NoError(t, err)
	assert.Zero(t, realmPunchWireLen("gecko", gecko))
	assert.Zero(t, realmPunchWireLen("plain", udp))
}
