package integration_tests

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/chameleon-protocol/chameleon/core/v2/client"
	"github.com/chameleon-protocol/chameleon/core/v2/internal/integration_tests/mocks"
	"github.com/chameleon-protocol/chameleon/core/v2/server"
)

// TestClientServerPaddingSeed makes sure a seeded padding scheme stays on the
// wire protocol: the padding is filler the peer skips, so any combination of
// seeds - including a seeded peer talking to one that was never configured -
// must still authenticate and proxy.
func TestClientServerPaddingSeed(t *testing.T) {
	tests := []struct {
		name       string
		serverSeed []byte
		clientSeed []byte
	}{
		{name: "both seeded", serverSeed: []byte("deployment secret"), clientSeed: []byte("deployment secret")},
		{name: "client only", clientSeed: []byte("deployment secret")},
		{name: "server only", serverSeed: []byte("deployment secret")},
		{name: "mismatched", serverSeed: []byte("one secret"), clientSeed: []byte("another secret")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server. Unlike the other integration tests this one
			// binds an ephemeral port, so that the four subtests can run back
			// to back without waiting for the previous socket to go away.
			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			assert.NoError(t, err)
			auth := mocks.NewMockAuthenticator(t)
			auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
			s, err := server.NewServer(&server.Config{
				TLSConfig:     serverTLSConfig(),
				Conn:          udpConn,
				Authenticator: auth,
				PaddingSeed:   tt.serverSeed,
			})
			assert.NoError(t, err)
			defer s.Close()
			go s.Serve()

			// Create TCP echo server
			echoListener, err := net.Listen("tcp", "127.0.0.1:0")
			assert.NoError(t, err)
			echoAddr := echoListener.Addr().String()
			echoServer := &tcpEchoServer{Listener: echoListener}
			defer echoServer.Close()
			go echoServer.Serve()

			// Create client
			c, _, err := client.NewClient(&client.Config{
				ServerAddr:  udpConn.LocalAddr(),
				TLSConfig:   client.TLSConfig{InsecureSkipVerify: true},
				PaddingSeed: tt.clientSeed,
			})
			assert.NoError(t, err)
			defer c.Close()

			// Dial TCP
			conn, err := c.TCP(echoAddr)
			assert.NoError(t, err)
			defer conn.Close()

			// Send and receive data
			sData := []byte("hello world")
			_, err = conn.Write(sData)
			assert.NoError(t, err)
			rData := make([]byte, len(sData))
			_, err = io.ReadFull(conn, rData)
			assert.NoError(t, err)
			assert.Equal(t, sData, rData)
		})
	}
}
