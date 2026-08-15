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
// The planned control protocol keys itself off a per-connection secret
// exported from the QUIC handshake:
//
//	discoSecret = conn.ConnectionState().TLS.ExportKeyingMaterial(...)
//
// The claim under test is not "can it be exported" but "do the two ends export
// the *same* value", including across session resumption and 0-RTT, which is
// exactly what a chameleon client does when it reconnects and what a P1
// candidate switch may trigger. The tests below run a real quic-go client and
// server over loopback UDP and compare the two sides byte for byte.
//
// The tests live in core because core is the module that owns the quic-go
// dependency and the two places that hold a *quic.Conn (core/client/client.go,
// core/server/server.go); a failure here is a failure of the fork's TLS
// plumbing, not of the disco code that does not exist yet. They deliberately
// talk to quic-go directly rather than through client.NewClient: the question is
// about the QUIC/TLS layer underneath HTTP/3, and going through /auth would only
// add moving parts between the exporter and the assertion.

const (
	// ekmLabel is the exporter label proposed in §1.4 of the disco design. RFC
	// 8446 §7.5 requires exporter labels to be unique per use; the value is
	// carried here verbatim so the spike measures the real thing.
	ekmLabel = "EXPORTER-chameleon-disco-v1"
	ekmALPN  = "chameleon-ekm-spike"
	ekmLen   = 32
)

// exportEKM calls the exporter exactly the way the disco design proposes to, and
// reports what actually happens.
//
// The panic recovery is not defensive noise: tls.ConnectionState holds the
// exporter as an unexported func field, so a ConnectionState that was rebuilt
// field by field (which is what the ChromeParrot/uTLS path does) carries a nil
// closure, and calling it is a nil func call -- a panic, not an error. Telling
// "unavailable" apart from "crashes the caller" is a result of this spike.
func exportEKM(conn *quic.Conn) (km []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ExportKeyingMaterial panicked: %v", r)
		}
	}()
	cs := conn.ConnectionState()
	return cs.TLS.ExportKeyingMaterial(ekmLabel, nil, ekmLen)
}

// ekmServer is a bare quic-go server that hands every accepted connection to a
// channel and echoes whatever arrives on the first stream.
type ekmServer struct {
	tr    *quic.Transport
	ln    *quic.EarlyListener
	addr  net.Addr
	conns chan *quic.Conn
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
	s := &ekmServer{tr: tr, ln: ln, addr: udpConn.LocalAddr(), conns: make(chan *quic.Conn, 4)}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			s.conns <- conn
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

func (s *ekmServer) accept(t *testing.T) *quic.Conn {
	t.Helper()
	select {
	case conn := <-s.conns:
		return conn
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
	sConn := s.accept(t)
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
	otherTLS := cConn.ConnectionState().TLS
	other, err := otherTLS.ExportKeyingMaterial("EXPORTER-chameleon-other-v1", nil, ekmLen)
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
	sConn1 := s.accept(t)
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

	// DialEarly returns before the handshake finishes when a ticket is available.
	// The exporter does not exist yet at that point: TLS 1.3 derives the exporter
	// master secret from the transcript through server Finished, and Go exposes no
	// early-exporter API at all. Only assert when the handshake really is still
	// running, so the check cannot flake on a fast loopback.
	if !cConn2.ConnectionState().TLS.HandshakeComplete {
		_, err := exportEKM(cConn2)
		require.Error(t, err, "the exporter must not be usable before the handshake completes")
		t.Logf("export before handshake completion: %v", err)
	}

	// The server accepts a 0-RTT connection before its own handshake is done, and
	// unlike the client it *can* already export there: crypto/tls installs the
	// server's exporter as soon as it has the master secret, which is before the
	// client's Finished arrives. The two ends are therefore not symmetric in when
	// the exporter appears, which is why disco must gate on HandshakeComplete
	// rather than on "the export call succeeded". The value itself is recorded
	// here and compared with the post-handshake one further down.
	sConn2 := s.accept(t)
	var sEKMEarly []byte
	if !sConn2.ConnectionState().TLS.HandshakeComplete {
		sEKMEarly, err = exportEKM(sConn2)
		t.Logf("server-side export during the 0-RTT window: len=%d err=%v", len(sEKMEarly), err)
	}

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
	if sEKMEarly != nil {
		require.Equal(t, sEKM2, sEKMEarly,
			"an early server-side export must not disagree with the post-handshake one")
	}
}

// TestEKMChromeParrot pins today's behaviour on the client default. ChromeParrot
// runs the client handshake through uTLS, and the adapter in the fork
// (internal/handshake/tls_conn_utls.go) rebuilds tls.ConnectionState field by
// field. The exporter closure is an unexported field, so it cannot be carried
// across and is nil: the design's expression does not merely fail on the default
// client, it panics.
func TestEKMChromeParrot(t *testing.T) {
	s := newEKMServer(t)
	cache := newSignallingCache()
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ekmALPN},
		ClientSessionCache: cache,
	}
	_, cConn := ekmClient(t, s, clientTLS, true)
	sConn := s.accept(t)
	waitHandshake(t, cConn)
	waitHandshake(t, sConn)
	roundTrip(t, cConn)

	// The server is plain crypto/tls regardless of what the client parrots, so
	// its half of the exporter works. Only the client half is missing, which is
	// enough to make the shared secret unobtainable.
	sEKM, err := exportEKM(sConn)
	require.NoError(t, err, "server side is crypto/tls and must still export")
	require.Len(t, sEKM, ekmLen)

	_, err = exportEKM(cConn)
	require.Error(t, err, "ChromeParrot client is expected to have no exporter today")
	t.Logf("ChromeParrot client-side export: %v", err)

	// ChromeParrot also turns session resumption off at the source (uTLS session
	// state cannot be converted into a *tls.SessionState), so on the default
	// client the whole 0-RTT question is moot: there is never a second
	// connection to be inconsistent with.
	select {
	case <-cache.stored:
		t.Fatal("ChromeParrot unexpectedly cached a session ticket")
	case <-time.After(500 * time.Millisecond):
	}
	_ = cConn.CloseWithError(0, "")

	_, cConn2 := ekmClient(t, s, clientTLS, true)
	sConn2 := s.accept(t)
	waitHandshake(t, cConn2)
	waitHandshake(t, sConn2)
	require.False(t, cConn2.ConnectionState().TLS.DidResume,
		"ChromeParrot must never resume, so 0-RTT cannot happen on the default client")
}
