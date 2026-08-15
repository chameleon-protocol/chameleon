package cmd

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreclient "github.com/chameleon-protocol/chameleon/core/v2/client"
	"github.com/chameleon-protocol/chameleon/extras/v2/obfs"
)

// firstWriteConn records the length of the first datagram written through it.
// It sits below the obfuscator, so what it sees is the length on the wire.
type firstWriteConn struct {
	net.PacketConn

	mu   sync.Mutex
	seen []int
}

func (c *firstWriteConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.seen = append(c.seen, len(p))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

func (c *firstWriteConn) first() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) == 0 {
		return 0, false
	}
	return c.seen[0], true
}

// TestPunchInitialWireLenMatchesTheRealHandshake is the pin under
// realmPunchInitialWireLen's two constants.
//
// They are quic-go's, unexported, and copied. A punch packet padded to a length
// that misses the real Initial by one byte is worse than one drawn from the
// fallback band: the whole reason to name a length is that it is the length
// this socket is about to send, and a near miss is a value nothing on the path
// produces. So the number is not trusted to a constant -- a real client is
// dialled and the first datagram it puts on the wire is measured.
//
// Nothing has to answer. The Initial goes out before any reply, which is
// exactly the moment a punch packet is imitating.
func TestPunchInitialWireLenMatchesTheRealHandshake(t *testing.T) {
	const password = "punch-length-pin"

	for _, tc := range []struct {
		name          string
		disableParrot bool
	}{
		{"chrome parrot", false},
		{"parrot disabled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer udp.Close()
			rec := &firstWriteConn{PacketConn: udp}

			wrapped, err := obfs.WrapPacketConnSalamanderV2(rec, []byte(password), "deployment", obfs.RoleClient)
			require.NoError(t, err)

			want := realmPunchInitialWireLen("salamander-v2", tc.disableParrot, wrapped)
			require.NotZero(t, want, "salamander v2 has a fixed overhead, so a length must be computable")

			// Nobody is listening on this address; the handshake fails after the
			// Initial has gone out, which is all this measures.
			dead := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
			_, _, _ = coreclient.NewClient(&coreclient.Config{
				ServerAddr:  dead,
				TLSConfig:   coreclient.TLSConfig{InsecureSkipVerify: true},
				QUICConfig:  coreclient.QUICConfig{DisableChromeParrot: tc.disableParrot},
				ConnFactory: &singleUseConnFactory{Open: func() (net.PacketConn, error) { return wrapped, nil }},
			})

			got, ok := rec.first()
			require.True(t, ok, "the client sent nothing")
			assert.Equal(t, want, got,
				"punch packets would be padded to %d while the handshake that follows them is %d bytes", want, got)
		})
	}
}

// A gecko-obfuscated socket has no single datagram length, so no length can be
// named for it and the fallback band is the honest answer.
func TestPunchInitialWireLenUnknownForGecko(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer udp.Close()

	wrapped, err := obfs.WrapPacketConnGecko(udp, obfs.GeckoOptions{Password: []byte("gecko-password")})
	require.NoError(t, err)
	assert.Zero(t, realmPunchInitialWireLen("gecko", false, wrapped))

	// And a socket with no obfuscator at all cannot be asked either.
	assert.Zero(t, realmPunchInitialWireLen("plain", false, udp))
}
