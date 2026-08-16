package client

import (
	"errors"
	"net"
	"testing"
)

// A reconnecting client has no connection between attempts, and a selector
// asking it to move candidates in that state must get an error rather than a
// dial. If SwitchTo reconnected, a selector cycling through candidates on a
// server that is down would keep the connection attempt running forever, which
// is the reconnect logic's decision to make and not the selector's.
func TestSwitchToWithoutAConnection(t *testing.T) {
	dialed := false
	c, err := NewReconnectableClient(func() (*Config, error) {
		dialed = true
		return nil, errors.New("the configuration must not be evaluated")
	}, nil, true /* lazy */)
	if err != nil {
		t.Fatalf("new lazy client: %v", err)
	}
	pc, ok := c.(PathController)
	if !ok {
		t.Fatal("a reconnectable client must be a PathController")
	}

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if err := pc.SwitchTo(addr); !errors.Is(err, ErrNoConnection) {
		t.Errorf("SwitchTo with no connection = %v, want %v", err, ErrNoConnection)
	}
	if got := pc.Current(); got != nil {
		t.Errorf("Current with no connection = %v, want nil", got)
	}
	if dialed {
		t.Error("asking where the connection is, or moving it, must not be what dials it")
	}
}
