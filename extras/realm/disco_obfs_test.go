package realm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/extras/v2/obfs"
)

// The disco gate is a structural interface and a string compare, so nothing in
// the compiler connects it to the method extras/obfs grows for it. Two things
// can drift apart silently: the method could disappear from a wrapper, and the
// name it reports could change. Either way disco would refuse to start, and the
// refusal would look like a configuration problem rather than a bug.
//
// extras/obfs asserts the method side at compile time (see obfuscationNamer in
// conn.go). This is the other half: the wrappers a deployment actually builds,
// put through the real gate.
func TestObfsConnsSatisfyTheDiscoGate(t *testing.T) {
	const password = "an-obfuscation-password"

	v2, err := obfs.WrapPacketConnSalamanderV2(listenUDP4(t), []byte(password), "test-realm", obfs.RoleClient)
	require.NoError(t, err)
	defer v2.Close()

	v1, err := obfs.WrapPacketConnSalamander(listenUDP4(t), []byte(password))
	require.NoError(t, err)
	defer v1.Close()

	gecko, err := obfs.WrapPacketConnGecko(listenUDP4(t), obfs.GeckoOptions{Password: []byte(password)})
	require.NoError(t, err)
	defer gecko.Close()

	for _, tc := range []struct {
		conn interface{ ObfuscationName() string }
		name string
	}{
		{v2.(interface{ ObfuscationName() string }), "salamander-v2"},
		{v1.(interface{ ObfuscationName() string }), "salamander"},
		{gecko.(interface{ ObfuscationName() string }), "gecko"},
	} {
		assert.Equal(t, tc.name, tc.conn.ObfuscationName())
	}

	// And the gate lets exactly one of them through. The two refusals are the
	// point: salamander v1 and gecko are the obfuscators whose backgrounds
	// nobody has captured, and gecko pads every datagram to a random size in a
	// range, so there is no modal length for a disco packet to copy at all.
	conn, err := NewDiscoPacketConn(v2, 4)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	_, err = NewDiscoPacketConn(v1, 4)
	assert.ErrorIs(t, err, ErrDiscoRequiresSalamanderV2)
	_, err = NewDiscoPacketConn(gecko, 4)
	assert.ErrorIs(t, err, ErrDiscoRequiresSalamanderV2)

	// A bare socket is the other refusal, and it is a different one: there is
	// nothing to derive a name from, not a name we do not like.
	_, err = NewDiscoPacketConn(listenUDP4(t), 4)
	assert.ErrorIs(t, err, ErrDiscoRequiresObfs)
}
