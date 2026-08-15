package auth

import (
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPAuthenticator(t *testing.T) {
	// Run the Python test auth server
	cmd := exec.Command("python", "http_test.py")
	err := cmd.Start()
	assert.NoError(t, err)
	defer cmd.Process.Kill()

	// Wait for the server to start. A fixed sleep here was long enough when
	// this package ran alone and not when the whole module's tests run in
	// parallel, which made this test fail for reasons that had nothing to do
	// with authentication.
	deadline := time.Now().Add(15 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:5000", time.Second)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("test auth server never came up: %v", dialErr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	auth := NewHTTPAuthenticator("http://127.0.0.1:5000/auth", false)

	ok, id := auth.Authenticate(&net.UDPAddr{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 34567,
	}, "idk", 123)
	assert.False(t, ok)
	assert.Equal(t, "", id)

	ok, id = auth.Authenticate(&net.UDPAddr{
		IP:   net.ParseIP("123.123.123.123"),
		Port: 5566,
	}, "wahaha", 12345)
	assert.True(t, ok)
	assert.Equal(t, "some_unique_id", id)
}
