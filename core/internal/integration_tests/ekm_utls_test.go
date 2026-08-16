package integration_tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

// ekm_test.go shows that the ChromeParrot client cannot export keying material
// today, because the fork's uTLS adapter rebuilds tls.ConnectionState field by
// field and the exporter closure is an unexported field it cannot copy
// (quic-go internal/handshake/tls_conn_utls.go, ConnectionState).
//
// The proposed fix is to plumb the exporter through as a method instead of
// through the struct: add ExportKeyingMaterial to the fork's tlsQUICConn
// interface and let the uTLS side delegate to uTLS's own
// (*utls.ConnectionState).ExportKeyingMaterial. That fix is only worth anything
// if uTLS and crypto/tls actually derive the *same* exporter, which is the
// premise this test checks: it drives a uTLS QUIC client against a crypto/tls
// QUIC server by hand -- no quic-go, no UDP, just the two TLS stacks exchanging
// handshake bytes -- and compares what each side exports.
//
// It lives here because the fork change has not been made yet and there is
// nowhere in it to hang the test; once ExportKeyingMaterial is plumbed through,
// this belongs next to that code in quic-go.
//
// The ClientHello is hand-built rather than taken from a uTLS HelloChrome_*
// preset for the same reason the fork builds its own: the presets are
// TLS-over-TCP fingerprints, they offer TLS 1.2, and a QUIC server rejects them
// outright. Only the properties this test depends on are reproduced (TLS 1.3
// only, a QUIC transport parameters extension); it is not a fingerprint.

const ekmUTLSLabel = "EXPORTER-chameleon-disco-v1"

func ekmUTLSCert(t *testing.T) tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ekm-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"ekm-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func ekmUTLSHelloSpec() *utls.ClientHelloSpec {
	alpn := []string{"h3"}
	return &utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
			}},
			&utls.ALPNExtension{AlpnProtocols: alpn},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.QUICTransportParametersExtension{TransportParameters: utls.TransportParameters{
				&utls.FakeQUICTransportParameter{Id: 0x01, Val: []byte{0x40, 0x67}},
			}},
		},
	}
}

// TestEKMAcrossTLSStacks drives a uTLS QUIC client against a crypto/tls QUIC server
// by hand, to see whether the two stacks derive the same exporter.
func TestEKMAcrossTLSStacks(t *testing.T) {
	cert := ekmUTLSCert(t)
	params := []byte{0x01, 0x02, 0x40, 0x67}

	srv := tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}})
	cli := utls.UQUICClient(&utls.QUICConfig{TLSConfig: &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         "ekm-test",
		NextProtos:         []string{"h3"},
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
	}}, utls.HelloCustom)
	if err := cli.ApplyPreset(ekmUTLSHelloSpec()); err != nil {
		t.Fatal(err)
	}
	cli.SetTransportParameters(params)
	srv.SetTransportParameters(params)

	ctx := context.Background()
	if err := cli.Start(ctx); err != nil {
		t.Fatal("client start:", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal("server start:", err)
	}

	cliDone, srvDone := false, false
	for i := 0; i < 200 && !(cliDone && srvDone); i++ {
		progress := false
		for {
			ev := cli.NextEvent()
			if ev.Kind == utls.QUICNoEvent {
				break
			}
			progress = true
			switch ev.Kind {
			case utls.QUICWriteData:
				if err := srv.HandleData(tls.QUICEncryptionLevel(ev.Level), ev.Data); err != nil {
					t.Fatal("server HandleData:", err)
				}
			case utls.QUICTransportParametersRequired:
				cli.SetTransportParameters(params)
			case utls.QUICHandshakeDone:
				cliDone = true
			}
		}
		for {
			ev := srv.NextEvent()
			if ev.Kind == tls.QUICNoEvent {
				break
			}
			progress = true
			switch ev.Kind {
			case tls.QUICWriteData:
				if err := cli.HandleData(utls.QUICEncryptionLevel(ev.Level), ev.Data); err != nil {
					t.Fatal("client HandleData:", err)
				}
			case tls.QUICTransportParametersRequired:
				srv.SetTransportParameters(params)
			case tls.QUICHandshakeDone:
				srvDone = true
			}
		}
		if !progress {
			break
		}
	}
	require.True(t, cliDone && srvDone, "handshake did not finish: client=%v server=%v", cliDone, srvDone)

	cs := cli.ConnectionState()
	cEKM, err := cs.ExportKeyingMaterial(ekmUTLSLabel, nil, ekmLen)
	require.NoError(t, err, "uTLS keeps its own exporter and must be able to run it")
	ss := srv.ConnectionState()
	sEKM, err := ss.ExportKeyingMaterial(ekmUTLSLabel, nil, ekmLen)
	require.NoError(t, err)
	require.Len(t, cEKM, ekmLen)
	require.Equal(t, sEKM, cEKM,
		"uTLS and crypto/tls must derive the same exporter, or plumbing it through the fork would not help")
}
