package integration_tests

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/time/rate"

	"github.com/chameleon-protocol/chameleon/core/v2/client"
	"github.com/chameleon-protocol/chameleon/core/v2/internal/integration_tests/mocks"
	"github.com/chameleon-protocol/chameleon/core/v2/server"
)

type tcpStressor struct {
	DialFunc   func() (net.Conn, error)
	Size       int
	Parallel   int
	Iterations int
}

func (s *tcpStressor) Run(t *testing.T) {
	// Make some random data
	sData := make([]byte, s.Size)
	_, err := rand.Read(sData)
	assert.NoError(t, err)

	// Run iterations
	for i := 0; i < s.Iterations; i++ {
		var wg sync.WaitGroup
		errChan := make(chan error, s.Parallel)
		for j := 0; j < s.Parallel; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				conn, err := s.DialFunc()
				if err != nil {
					errChan <- err
					return
				}
				defer conn.Close()
				go conn.Write(sData)

				rData := make([]byte, len(sData))
				_, err = io.ReadFull(conn, rData)
				if err != nil {
					errChan <- err
					return
				}
			}()
		}
		wg.Wait()

		assert.Empty(t, errChan)
	}
}

type udpStressor struct {
	ListenFunc func() (client.HyUDPConn, error)
	ServerAddr string
	Size       int
	Count      int
	Parallel   int
	Iterations int
}

func (s *udpStressor) Run(t *testing.T) {
	// Make some random data
	sData := make([]byte, s.Size)
	_, err := rand.Read(sData)
	assert.NoError(t, err)

	// Due to UDP's unreliability, we need to limit the rate of sending
	// to reduce packet loss. This is hardcoded to 1 MiB/s for now.
	//
	// The burst is one packet, not one second's worth. With a burst of 1 MiB
	// the limiter never engaged for any case below 1 MiB total -- including
	// "Single 1000x100b", which sends 100 KiB -- so the packets went out as
	// fast as the loop could push them and the rate above meant nothing.
	// Datagrams have no retransmission and quic-go's receive queue holds 128,
	// so an unpaced burst of 1000 loses ~30% on a fast host and the case
	// deadlocks against its own 20% tolerance.
	limiter := rate.NewLimiter(1048576, s.Size)

	// Run iterations
	for i := 0; i < s.Iterations; i++ {
		var wg sync.WaitGroup
		errChan := make(chan error, s.Parallel)
		for j := 0; j < s.Parallel; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				conn, err := s.ListenFunc()
				if err != nil {
					errChan <- err
					return
				}
				defer conn.Close()
				go func() {
					// Sending routine
					for i := 0; i < s.Count; i++ {
						_ = limiter.WaitN(context.Background(), len(sData))
						_ = conn.Send(sData, s.ServerAddr)
					}
				}()

				minCount := s.Count * 8 / 10 // Tolerate 20% packet loss
				for i := 0; i < minCount; i++ {
					rData, _, err := conn.Receive()
					if err != nil {
						errChan <- err
						return
					}
					if len(rData) != len(sData) {
						errChan <- fmt.Errorf("incomplete data received: %d/%d bytes", len(rData), len(sData))
						return
					}
				}
			}()
		}
		wg.Wait()

		assert.Empty(t, errChan)
	}
}

func TestClientServerTCPStress(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create TCP echo server
	echoAddr := "127.0.0.1:22333"
	echoListener, err := net.Listen("tcp", echoAddr)
	assert.NoError(t, err)
	echoServer := &tcpEchoServer{Listener: echoListener}
	defer echoServer.Close()
	go echoServer.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	dialFunc := func() (net.Conn, error) {
		return c.TCP(echoAddr)
	}

	t.Run("Single 500m", (&tcpStressor{DialFunc: dialFunc, Size: 524288000, Parallel: 1, Iterations: 1}).Run)

	t.Run("Sequential 1000x1m", (&tcpStressor{DialFunc: dialFunc, Size: 1048576, Parallel: 1, Iterations: 1000}).Run)
	t.Run("Sequential 10000x100k", (&tcpStressor{DialFunc: dialFunc, Size: 102400, Parallel: 1, Iterations: 10000}).Run)

	t.Run("Parallel 100x10m", (&tcpStressor{DialFunc: dialFunc, Size: 10485760, Parallel: 100, Iterations: 1}).Run)
	t.Run("Parallel 1000x1m", (&tcpStressor{DialFunc: dialFunc, Size: 1048576, Parallel: 1000, Iterations: 1}).Run)
}

func TestClientServerUDPStress(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create UDP echo server
	echoAddr := "127.0.0.1:22333"
	echoConn, err := net.ListenPacket("udp", echoAddr)
	assert.NoError(t, err)
	echoServer := &udpEchoServer{Conn: echoConn}
	defer echoServer.Close()
	go echoServer.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	t.Run("Single 1000x100b", (&udpStressor{
		ListenFunc: c.UDP,
		ServerAddr: echoAddr,
		Size:       100,
		Count:      1000,
		Parallel:   1,
		Iterations: 1,
	}).Run)
	t.Run("Single 1000x3k", (&udpStressor{
		ListenFunc: c.UDP,
		ServerAddr: echoAddr,
		Size:       3000,
		Count:      1000,
		Parallel:   1,
		Iterations: 1,
	}).Run)

	t.Run("5 Sequential 1000x100b", (&udpStressor{
		ListenFunc: c.UDP,
		ServerAddr: echoAddr,
		Size:       100,
		Count:      1000,
		Parallel:   1,
		Iterations: 5,
	}).Run)
	t.Run("5 Sequential 200x3k", (&udpStressor{
		ListenFunc: c.UDP,
		ServerAddr: echoAddr,
		Size:       3000,
		Count:      200,
		Parallel:   1,
		Iterations: 5,
	}).Run)

	t.Run("2 Sequential 5 Parallel 1000x100b", (&udpStressor{
		ListenFunc: c.UDP,
		ServerAddr: echoAddr,
		Size:       100,
		Count:      1000,
		Parallel:   5,
		Iterations: 2,
	}).Run)
	t.Run("2 Sequential 5 Parallel 200x3k", (&udpStressor{
		ListenFunc: c.UDP,
		ServerAddr: echoAddr,
		Size:       3000,
		Count:      200,
		Parallel:   5,
		Iterations: 2,
	}).Run)
}
