// Package harness brings up a real core server and a real core client with an
// impaired link between them, and measures what gets through.
//
// Everything a test asserts on -- throughput, latency percentiles, failover
// time -- is produced here, so that acceptance criteria elsewhere in the
// project can name a profile and a number instead of describing a setup.
package harness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"

	"github.com/apernet/hysteria/tests/v2/netem"
)

// Options configures an Env. The zero value gives a clean link, a one-shot
// client and the core's default QUIC parameters.
type Options struct {
	// Profile is the impairment in force when the Env comes up. Tests change it
	// mid-flight through Env.Ctrl.
	Profile netem.Profile

	// Seed makes the link's loss and jitter draws reproducible.
	Seed uint64

	// MaxIdleTimeout overrides the QUIC idle timeout on both ends. The default
	// is 30s, which is how long a failover test would otherwise wait for the
	// client to notice a dead link; 4s is the minimum the core accepts.
	MaxIdleTimeout time.Duration

	// KeepAlivePeriod overrides the client's keep-alive interval.
	KeepAlivePeriod time.Duration

	// Reconnect builds a reconnectable client, which is required to measure
	// anything about recovery: a plain client is dead once its QUIC connection
	// is.
	Reconnect bool
}

// Env is a running server, client and echo server, plus the handle that
// controls the link between them.
type Env struct {
	T      testing.TB
	Ctrl   *netem.Controller
	Client client.Client

	// TCPEcho is the address of a TCP echo server, reachable only by asking the
	// proxy to dial it.
	TCPEcho string
	// UDPEcho is the address of a UDP echo server.
	UDPEcho string

	ServerAddr net.Addr
}

// New brings up the whole path and registers its teardown with t. It fails the
// test if the client cannot connect.
func New(t testing.TB, opts Options) *Env {
	t.Helper()
	env, err := TryNew(t, opts)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return env
}

// TryNew is New for tests that expect the client not to come up -- a link that
// blocks UDP outright, for instance. Only the client's connection attempt is
// reported as an error; anything else that goes wrong is a harness bug and
// fails the test.
func TryNew(t testing.TB, opts Options) (*Env, error) {
	t.Helper()

	ctrl := netem.NewController(opts.Profile)
	ctrl.SetSeed(opts.Seed)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server socket: %v", err)
	}
	sv, err := server.NewServer(&server.Config{
		TLSConfig:     server.TLSConfig{Certificates: []tls.Certificate{selfSignedCert(t)}},
		QUICConfig:    server.QUICConfig{MaxIdleTimeout: opts.MaxIdleTimeout},
		Conn:          serverConn,
		Authenticator: allowAll{},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go sv.Serve()
	t.Cleanup(func() { _ = sv.Close() })

	tcpEcho := startTCPEcho(t)
	udpEcho := startUDPEcho(t)

	serverAddr := serverConn.LocalAddr()
	configFunc := func() (*client.Config, error) {
		return &client.Config{
			ConnFactory: netem.ConnFactory{Controller: ctrl},
			ServerAddr:  serverAddr,
			TLSConfig:   client.TLSConfig{InsecureSkipVerify: true},
			QUICConfig: client.QUICConfig{
				MaxIdleTimeout:  opts.MaxIdleTimeout,
				KeepAlivePeriod: opts.KeepAlivePeriod,
			},
		}, nil
	}

	var c client.Client
	if opts.Reconnect {
		c, err = client.NewReconnectableClient(configFunc, nil, false)
	} else {
		config, cfgErr := configFunc()
		if cfgErr != nil {
			t.Fatalf("client config: %v", cfgErr)
		}
		c, _, err = client.NewClient(config)
	}
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close() })

	return &Env{
		T:          t,
		Ctrl:       ctrl,
		Client:     c,
		TCPEcho:    tcpEcho,
		UDPEcho:    udpEcho,
		ServerAddr: serverAddr,
	}, nil
}

type allowAll struct{}

func (allowAll) Authenticate(net.Addr, string, uint64) (bool, string) { return true, "test" }

func selfSignedCert(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "netem-testbed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
