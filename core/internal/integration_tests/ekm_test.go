package integration_tests

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/chameleon-protocol/quic-go"
	"github.com/stretchr/testify/require"
)

// This file covers the TLS exporter (RFC 5705 / RFC 8446 §7.5).
//
// The planned control protocol keys itself off a per-connection secret exported
// from the QUIC handshake, via the fork's (*quic.Conn).ExportKeyingMaterial.
// That method exists because the obvious expression,
// conn.ConnectionState().TLS.ExportKeyingMaterial(...), does not work on the
// client chameleon actually ships: tls.ConnectionState keeps the exporter in an
// unexported func field, the ChromeParrot client's state is rebuilt field by
// field out of uTLS's, and calling a nil func value panics rather than failing.
// The measurement that produced the method is what these tests now guard.
//
// The claims under test are that both ends export the *same* value, that the
// value is fresh per connection across session resumption and 0-RTT (what a
// chameleon reconnect and a P1 candidate switch do), that the ChromeParrot
// client can export at all, and that neither end can export before its handshake
// completes. The tests run a real quic-go client and server over loopback UDP
// and compare the two sides byte for byte.
//
// The tests live in core because core is the module that owns the quic-go
// dependency and the two places that hold a *quic.Conn (core/client/client.go,
// core/server/server.go); a failure here is a failure of the fork's TLS
// plumbing, not of the disco code that does not exist yet. They deliberately
// talk to quic-go directly rather than through client.NewClient: the question is
// about the QUIC/TLS layer underneath HTTP/3, and going through /auth would only
// add moving parts between the exporter and the assertion.

const (
	// ekmLabel is the exporter label proposed for the disco secret. RFC 8446 §7.5
	// requires exporter labels to be unique per use; the value is carried here
	// verbatim so the tests measure the real thing.
	ekmLabel = "EXPORTER-chameleon-disco-v1"
	ekmALPN  = "chameleon-ekm-spike"
	ekmLen   = 32

	// ekmTooEarly is the fork's own refusal. crypto/tls has a refusal of its own
	// for the client's pre-handshake case, with different (and misleading) text,
	// so matching this string is what distinguishes "the guard held" from "the
	// TLS stack happened to say no anyway".
	ekmTooEarly = "before the handshake completes"
)

// exportEKM calls the exporter the way the disco code will.
//
// The panic recovery is not defensive noise about the current API but a guard
// against regressing to the old one: if the exporter ever again comes from a
// rebuilt tls.ConnectionState, the failure is a nil func call, and a panicking
// test binary reports far worse than a failed assertion.
func exportEKM(conn *quic.Conn) (km []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ExportKeyingMaterial panicked: %v", r)
		}
	}()
	return conn.ExportKeyingMaterial(ekmLabel, nil, ekmLen)
}

// ekmServer is a bare quic-go server that hands every accepted connection to a
// channel and echoes whatever arrives on the first stream.
type ekmServer struct {
	tr    *quic.Transport
	ln    *quic.EarlyListener
	addr  net.Addr
	conns chan *ekmAccepted
}

// ekmAccepted is what the accept loop saw at the instant a connection was handed
// over, plus the connection itself.
//
// The pre-handshake sample has to be taken there rather than after the test
// goroutine gets around to reading the channel: with ListenEarly and Allow0RTT
// the server is handed a connection inside the 0-RTT window, and that window
// closes as soon as the client's Finished arrives. Sampling late would not fail,
// it would silently stop covering the pre-handshake case.
type ekmAccepted struct {
	conn *quic.Conn
	// handshakeDone reports whether the handshake had already finished by the
	// time Accept returned, i.e. whether there was a window to sample at all.
	handshakeDone bool
	earlyEKM      []byte
	earlyErr      error
}

func newEKMServer(t *testing.T) *ekmServer {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(testCertFile, testKeyFile)
	require.NoError(t, err)
	// Port 0: the shared serverConn() helper pins 14514, and these tests must be
	// able to run alongside the rest of the package.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.ListenEarly(
		&tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{ekmALPN},
		},
		// Allow0RTT is what makes the resumption subtest able to reach the 0-RTT
		// path at all; without it the server rejects early data and the second
		// handshake degrades to a plain 1-RTT resumption.
		&quic.Config{Allow0RTT: true},
	)
	require.NoError(t, err)
	s := &ekmServer{tr: tr, ln: ln, addr: udpConn.LocalAddr(), conns: make(chan *ekmAccepted, 4)}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			a := &ekmAccepted{conn: conn}
			if handshakeDone(conn) {
				a.handshakeDone = true
			} else {
				a.earlyEKM, a.earlyErr = exportEKM(conn)
			}
			s.conns <- a
			go s.echo(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = tr.Close()
		_ = udpConn.Close()
	})
	return s
}

func (s *ekmServer) echo(conn *quic.Conn) {
	str, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}
	_, _ = io.Copy(str, str)
	_ = str.Close()
}

func (s *ekmServer) accept(t *testing.T) *ekmAccepted {
	t.Helper()
	select {
	case a := <-s.conns:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept a connection")
		return nil
	}
}

// signallingCache is an LRU session cache that also announces stores, so the
// resumption subtest can wait for the session ticket instead of sleeping. The
// ticket arrives after the handshake finishes, so redialling immediately is a
// race that would show up as a flaky "did not resume".
type signallingCache struct {
	tls.ClientSessionCache
	stored chan struct{}
}

func newSignallingCache() *signallingCache {
	return &signallingCache{
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
		stored:             make(chan struct{}, 8),
	}
}

func (c *signallingCache) Put(key string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, cs)
	select {
	case c.stored <- struct{}{}:
	default:
	}
}

// ekmClient dials the spike server. Each dial gets its own PacketConn and
// Transport, which is what a chameleon reconnect does (client.connect() builds
// both from scratch every time).
func ekmClient(t *testing.T, s *ekmServer, tlsConf *tls.Config, parrot bool) (*quic.Transport, *quic.Conn) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udpConn}
	if parrot {
		// Mirrors core/client/client.go: Chrome uses a zero-length source
		// connection ID, and that has to be set on the Transport.
		tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.DialEarly(ctx, s.addr, tlsConf, &quic.Config{ChromeParrot: parrot})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = tr.Close()
		_ = udpConn.Close()
	})
	return tr, conn
}

func waitHandshake(t *testing.T, conn *quic.Conn) {
	t.Helper()
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not complete")
	}
}

// handshakeDone reports whether the handshake has finished, without waiting for
// it. HandshakeComplete is the only reliable signal on either end: the client's
// TLS stack reports a version and a completion flag that are not yet meaningful
// while the handshake is still running.
func handshakeDone(conn *quic.Conn) bool {
	select {
	case <-conn.HandshakeComplete():
		return true
	default:
		return false
	}
}

// roundTrip pushes bytes through a stream so that the exporter can be sampled
// again after real 1-RTT traffic, not only at the instant the handshake ends.
func roundTrip(t *testing.T, conn *quic.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	payload := []byte("disco spike payload")
	_, err = str.Write(payload)
	require.NoError(t, err)
	buf := make([]byte, len(payload))
	_, err = io.ReadFull(str, buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf)
	_ = str.Close()
}

// TestEKMStdlibPath is the main result: on the crypto/tls path (ChromeParrot
// off) the exporter is available on both ends, both ends agree, and the value is
// stable for the life of the connection.
func TestEKMStdlibPath(t *testing.T) {
	s := newEKMServer(t)
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ekmALPN},
	}
	_, cConn := ekmClient(t, s, clientTLS, false)
	sConn := s.accept(t).conn
	waitHandshake(t, cConn)
	// The server's handshake only completes when the client's Finished arrives,
	// so it needs its own wait; sampling it right after Accept is a race.
	waitHandshake(t, sConn)

	cEKM, err := exportEKM(cConn)
	require.NoError(t, err, "client-side export right after the handshake")
	sEKM, err := exportEKM(sConn)
	require.NoError(t, err, "server-side export right after the handshake")
	require.Len(t, cEKM, ekmLen)
	require.Equal(t, cEKM, sEKM, "the two ends must export the same secret")

	roundTrip(t, cConn)

	cEKM2, err := exportEKM(cConn)
	require.NoError(t, err)
	sEKM2, err := exportEKM(sConn)
	require.NoError(t, err)
	require.Equal(t, cEKM, cEKM2, "exporter must not change once 1-RTT data flows")
	require.Equal(t, sEKM, sEKM2)

	// Different labels must give different keys, otherwise the design's
	// per-purpose derivation would collapse into one key.
	other, err := cConn.ExportKeyingMaterial("EXPORTER-chameleon-other-v1", nil, ekmLen)
	require.NoError(t, err)
	require.NotEqual(t, cEKM, other)
}

// TestEKMResumptionAndZeroRTT is the question the review actually asked: after a
// resumption -- with 0-RTT where the stack takes it -- do the two ends still
// export the same value, and is that value fresh rather than inherited from the
// previous connection?
func TestEKMResumptionAndZeroRTT(t *testing.T) {
	s := newEKMServer(t)
	cache := newSignallingCache()
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ekmALPN},
		ClientSessionCache: cache,
		// Required, not cosmetic: crypto/tls keys the client session cache by
		// ServerName, and under QUIC there is no net.Conn to fall back to a
		// remote address. With ServerName empty the cache key is "" and tickets
		// are silently dropped, i.e. resumption never happens at all.
		ServerName: "chameleon-ekm-spike",
	}

	_, cConn1 := ekmClient(t, s, clientTLS, false)
	sConn1 := s.accept(t).conn
	waitHandshake(t, cConn1)
	waitHandshake(t, sConn1)
	cEKM1, err := exportEKM(cConn1)
	require.NoError(t, err)
	sEKM1, err := exportEKM(sConn1)
	require.NoError(t, err)
	require.Equal(t, cEKM1, sEKM1)

	// Wait for the session ticket before redialling, or the second connection is
	// a fresh handshake and this test silently stops testing resumption.
	select {
	case <-cache.stored:
	case <-time.After(5 * time.Second):
		t.Fatal("no session ticket was cached")
	}
	_ = cConn1.CloseWithError(0, "")

	_, cConn2 := ekmClient(t, s, clientTLS, false)

	// DialEarly returns before the handshake finishes when a ticket is available,
	// which is the client half of the timing rule. There is genuinely nothing to
	// export yet -- TLS 1.3 derives the exporter master secret from a transcript
	// that runs through server Finished, and Go exposes no early-exporter API --
	// so crypto/tls would refuse anyway, but with its own misleading text about
	// version negotiation. Matching the fork's wording is what makes this assert
	// the guard rather than the accident.
	clientWindow := !handshakeDone(cConn2)
	if clientWindow {
		_, err := exportEKM(cConn2)
		require.Error(t, err, "the exporter must not be usable before the handshake completes")
		require.Contains(t, err.Error(), ekmTooEarly,
			"the refusal must come from the handshake guard, not from whatever the TLS stack says")
	}

	// The server half is where the guard earns its keep: crypto/tls installs the
	// server's exporter as soon as it has the master secret, which is before the
	// client's Finished arrives, so inside the 0-RTT window the raw stack exports
	// a value the client cannot yet compute. That sample is taken in the accept
	// loop; see ekmAccepted.
	sa2 := s.accept(t)
	if !sa2.handshakeDone {
		require.Error(t, sa2.earlyErr,
			"the server must refuse inside the 0-RTT window even though its TLS stack could export there")
		require.Contains(t, sa2.earlyErr.Error(), ekmTooEarly)
		require.Nil(t, sa2.earlyEKM)
	}
	// Both windows are opened by timing, so record whether they were actually
	// reached; a run where neither was is a run that did not test the guard.
	t.Logf("pre-handshake windows observed: client=%v server=%v", clientWindow, !sa2.handshakeDone)
	require.True(t, clientWindow || !sa2.handshakeDone,
		"neither end was sampled before its handshake completed, so the timing rule went untested")
	sConn2 := sa2.conn

	// Writing before the handshake completes is what makes the data 0-RTT.
	roundTrip(t, cConn2)
	waitHandshake(t, cConn2)
	waitHandshake(t, sConn2)

	require.True(t, cConn2.ConnectionState().TLS.DidResume, "second connection must resume")
	// Whether 0-RTT is actually taken depends on timing and on the server's
	// Allow0RTT decision, so it is reported rather than required.
	t.Logf("resumed connection: DidResume=%v client Used0RTT=%v server Used0RTT=%v",
		cConn2.ConnectionState().TLS.DidResume,
		cConn2.ConnectionState().Used0RTT,
		sConn2.ConnectionState().Used0RTT)

	cEKM2, err := exportEKM(cConn2)
	require.NoError(t, err, "client-side export on a resumed connection")
	sEKM2, err := exportEKM(sConn2)
	require.NoError(t, err, "server-side export on a resumed connection")
	require.Equal(t, cEKM2, sEKM2, "the two ends must agree across resumption")
	require.NotEqual(t, cEKM1, cEKM2,
		"a resumed connection must export a fresh secret, or disco keys would survive a reconnect")
}

// TestEKMChromeParrot covers the client chameleon actually ships. ChromeParrot
// runs the client handshake through uTLS while the server stays on crypto/tls,
// so this is the case where the exporter has to cross two TLS implementations:
// the fork reaches uTLS's own exporter through a method, because the
// tls.ConnectionState the adapter rebuilds cannot carry the closure.
//
// This is the load-bearing test of the whole exercise. If the client half ever
// stops delegating to uTLS, the two ends stop agreeing here.
func TestEKMChromeParrot(t *testing.T) {
	s := newEKMServer(t)
	cache := newSignallingCache()
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ekmALPN},
		ClientSessionCache: cache,
	}
	_, cConn := ekmClient(t, s, clientTLS, true)
	sConn := s.accept(t).conn
	waitHandshake(t, cConn)
	waitHandshake(t, sConn)
	roundTrip(t, cConn)

	cEKM, err := exportEKM(cConn)
	require.NoError(t, err, "the ChromeParrot client must be able to export")
	require.Len(t, cEKM, ekmLen)

	// The server is plain crypto/tls regardless of what the client parrots. Equal
	// values here mean uTLS's exporter and crypto/tls's agree on the same
	// handshake, which is the property the whole scheme rests on.
	sEKM, err := exportEKM(sConn)
	require.NoError(t, err, "server side is crypto/tls and must still export")
	require.Equal(t, cEKM, sEKM, "uTLS client and crypto/tls server must export the same secret")

	other, err := cConn.ExportKeyingMaterial("EXPORTER-chameleon-other-v1", nil, ekmLen)
	require.NoError(t, err)
	require.NotEqual(t, cEKM, other, "labels must separate keys on the uTLS path too")

	// ChromeParrot turns session resumption off at the source (uTLS session state
	// cannot be converted into a *tls.SessionState), so on the default client the
	// whole 0-RTT question is moot: there is never a second connection to be
	// inconsistent with.
	select {
	case <-cache.stored:
		t.Fatal("ChromeParrot unexpectedly cached a session ticket")
	case <-time.After(500 * time.Millisecond):
	}
	_ = cConn.CloseWithError(0, "")

	_, cConn2 := ekmClient(t, s, clientTLS, true)
	sConn2 := s.accept(t).conn
	waitHandshake(t, cConn2)
	waitHandshake(t, sConn2)
	require.False(t, cConn2.ConnectionState().TLS.DidResume,
		"ChromeParrot must never resume, so 0-RTT cannot happen on the default client")

	cEKM2, err := exportEKM(cConn2)
	require.NoError(t, err)
	sEKM2, err := exportEKM(sConn2)
	require.NoError(t, err)
	require.Equal(t, cEKM2, sEKM2)
	require.NotEqual(t, cEKM, cEKM2,
		"a reconnect must export a fresh secret on the parrot path as well")
}
