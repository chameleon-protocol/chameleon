package realm

import (
	"context"
)

// ServerPuncher is the responder side of a Puncher, kept as its own type so the
// server's call sites read as what they are. Every attempt it runs shares the
// listening socket with the QUIC server on top of it.
type ServerPuncher struct {
	*Puncher
}

// NewServerPuncher returns a puncher bound to conn. Attempts stop when ctx is
// cancelled, so the server's shutdown context also shuts down punching.
func NewServerPuncher(ctx context.Context, conn *PunchPacketConn) (*ServerPuncher, error) {
	puncher, err := newPuncher(ctx, conn)
	if err != nil {
		return nil, err
	}
	return &ServerPuncher{Puncher: puncher}, nil
}
