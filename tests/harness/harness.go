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

	"github.com/chameleon-protocol/chameleon/core/v2/client"
	"github.com/chameleon-protocol/chameleon/core/v2/server"

	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
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

	// Candidates, when greater than one, puts a MultiPath in front of the server
	// socket: the server becomes reachable at that many distinct 127.0.0.1
	// addresses, each impairable on its own through Ctrl.SetFor. The client
	// dials the first of them.
	//
	// It is what lets a multi-candidate scenario be written down before a
	// Selector exists to choose between candidates. Until one does, the client
	// still has exactly one ServerAddr, so the other legs are reachable but
	// unused -- which is itself the thing several tests are about.
	Candidates int

	// Bandwidth declares a rate on both ends, which is the only way to get the
	// Brutal congestion controller installed: the core falls back to the
	// configured controller (BBR) whenever either side's declaration is zero.
	// Without this an Env measures BBR no matter what the profile says.
	Bandwidth Bandwidth
}

// Bandwidth is what both ends declare to each other during authentication. The
// negotiated send rate is min(peer's Rx, own Tx) on each side, so setting Tx
// and Rx to the same value on both ends makes the declared rate exactly that
// value in both directions.
type Bandwidth struct {
	// BytesPerSec is the rate both ends declare. Zero leaves Brutal out and the
	// connection on the configured controller. The core rejects anything below
	// 65536.
	BytesPerSec uint64

	// DisableLossCompensation turns off Brutal's ackRate divisor on both ends,
	// which is the A/B switch for the loss-compensation behaviour.
	DisableLossCompensation bool
}

// Env is a running server, client and echo server, plus the handle that
// controls the link between them.
type Env struct {
	T testing.TB

	// closeServer releases the server socket. Cleanup on the TB does it too;
	// this exists so a caller that builds many environments in one test or
	// benchmark can release each one as it finishes instead of holding all of
	// them open until the TB is done.
	closeServer func()
	Ctrl        *netem.Controller
	Client      client.Client

	// TCPEcho is the address of a TCP echo server, reachable only by asking the
	// proxy to dial it.
	TCPEcho string
	// UDPEcho is the address of a UDP echo server.
	UDPEcho string

	// ServerAddr is the address the client dialled, which is a MultiPath leg
	// when Options.Candidates asked for one and the server socket otherwise.
	// AddClient reaches the server the same way the first client did.
	ServerAddr net.Addr

	// Paths is the forwarder in front of the server, or nil when
	// Options.Candidates did not ask for one.
	Paths *MultiPath
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
		TLSConfig:  server.TLSConfig{Certificates: []tls.Certificate{selfSignedCert(t)}},
		QUICConfig: server.QUICConfig{MaxIdleTimeout: opts.MaxIdleTimeout},
		BandwidthConfig: server.BandwidthConfig{
			MaxTx:                   opts.Bandwidth.BytesPerSec,
			MaxRx:                   opts.Bandwidth.BytesPerSec,
			DisableLossCompensation: opts.Bandwidth.DisableLossCompensation,
		},
		Conn:          serverConn,
		Authenticator: allowAll{},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go sv.Serve()
	closeServer := func() { _ = sv.Close() }
	t.Cleanup(closeServer)

	tcpEcho := startTCPEcho(t)
	udpEcho := startUDPEcho(t)

	serverAddr := serverConn.LocalAddr()
	var paths *MultiPath
	if opts.Candidates > 0 {
		paths = NewMultiPath(t, serverAddr, opts.Candidates)
		serverAddr = paths.Legs[0].Addr()
	}
	c, err := dialClient(t, ctrl, serverAddr, opts)
	if err != nil {
		return nil, err
	}

	return &Env{
		T:           t,
		Ctrl:        ctrl,
		Client:      c,
		closeServer: closeServer,
		TCPEcho:     tcpEcho,
		UDPEcho:     udpEcho,
		ServerAddr:  serverAddr,
		Paths:       paths,
	}, nil
}

// Close releases the environment now rather than when the test or benchmark
// that built it finishes. Calling it is optional and calling it twice is
// harmless -- the TB cleanup still runs -- but a loop that builds one
// environment per iteration holds every server socket it ever opened until the
// TB is done unless it closes them as it goes.
func (e *Env) Close() {
	if e.closeServer != nil {
		e.closeServer()
	}
	if e.Client != nil {
		_ = e.Client.Close()
	}
}

// dialClient brings up one client against serverAddr over ctrl's link.
func dialClient(t testing.TB, ctrl *netem.Controller, serverAddr net.Addr, opts Options) (client.Client, error) {
	configFunc := func() (*client.Config, error) {
		return &client.Config{
			ConnFactory: netem.ConnFactory{Controller: ctrl},
			ServerAddr:  serverAddr,
			TLSConfig:   client.TLSConfig{InsecureSkipVerify: true},
			QUICConfig: client.QUICConfig{
				MaxIdleTimeout:  opts.MaxIdleTimeout,
				KeepAlivePeriod: opts.KeepAlivePeriod,
			},
			BandwidthConfig: client.BandwidthConfig{
				MaxTx:                   opts.Bandwidth.BytesPerSec,
				MaxRx:                   opts.Bandwidth.BytesPerSec,
				DisableLossCompensation: opts.Bandwidth.DisableLossCompensation,
			},
		}, nil
	}

	var (
		c   client.Client
		err error
	)
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
	return c, nil
}

// Peer is a second client on the same server, with its own link and its own
// counters.
//
// It exists so that two flows can be measured against each other. Each Peer
// gets its own Controller, because Controller.Stats sums every Conn it made and
// a shared one could not say which flow moved which bytes; the two Controllers
// are made to share a bottleneck by pointing both profiles' Links at the same
// netem.Bottleneck.
type Peer struct {
	Client client.Client
	Ctrl   *netem.Controller
}

// AddClient brings up another client against the same server. The server's
// bandwidth declaration is fixed when the Env comes up, so the negotiated rate
// is min(server's, this client's): a Peer with a zero Bandwidth gets BBR
// regardless of what the first client declared.
func (e *Env) AddClient(profile netem.Profile, seed uint64, opts Options) (*Peer, error) {
	e.T.Helper()
	ctrl := netem.NewController(profile)
	ctrl.SetSeed(seed)
	c, err := dialClient(e.T, ctrl, e.ServerAddr, opts)
	if err != nil {
		return nil, err
	}
	return &Peer{Client: c, Ctrl: ctrl}, nil
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
