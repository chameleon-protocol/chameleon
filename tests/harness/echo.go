package harness

import (
	"io"
	"net"
	"testing"
)

// startTCPEcho runs a TCP echo server on loopback and returns its address. It
// is the far end of the tunnel: traffic reaches it only by asking the proxy to
// dial it, so everything measured against it crossed the impaired link.
func startTCPEcho(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// startUDPEcho runs a UDP echo server on loopback and returns its address.
func startUDPEcho(t testing.TB) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}
