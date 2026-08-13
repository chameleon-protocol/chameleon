package realm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"
)

// Puncher runs punch attempts over a PunchPacketConn.
//
// It holds no read loop of its own: inbound punch packets come from the conn's
// demux, which keeps working while QUIC owns the socket. An attempt can
// therefore start at any point in the socket's life — before the connection
// exists, and again after a network change while data is flowing — and several
// attempts can run at once as long as they use different attempt IDs.
//
// Before QUIC owns the socket, nothing is reading it; call
// PunchPacketConn.StartPump to have the demux fed in the meantime.
type Puncher struct {
	conn *PunchPacketConn
	// base is the lifetime of the puncher. Attempts derive from it, so
	// cancelling it stops them all.
	base context.Context
}

func NewPuncher(conn *PunchPacketConn) (*Puncher, error) {
	return newPuncher(context.Background(), conn)
}

func newPuncher(ctx context.Context, conn *PunchPacketConn) (*Puncher, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: conn is nil", ErrInvalidPunchAttempt)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &Puncher{conn: conn, base: ctx}, nil
}

// Punch runs the initiator side of a punch attempt: it sends hello packets to
// the peer candidates, acks inbound hellos, and returns as soon as it sees a
// valid punch packet from an accepted source. If none arrives before the
// timeout, it returns ErrPunchTimeout.
//
// It accepts punch packets only from the candidate set by default, so a
// rendezvous server cannot answer with an address the peer never announced.
func (p *Puncher) Punch(ctx context.Context, attemptID string, localAddrs, peerAddrs []netip.AddrPort, meta PunchMetadata, config PunchConfig) (PunchResult, error) {
	return p.run(ctx, attemptID, localAddrs, peerAddrs, meta, config, PunchSourceCandidates)
}

// Respond runs the responder side of a punch attempt.
//
// Unlike Punch, it accepts any source by default: a peer behind a symmetric
// NAT arrives from a port nobody can predict, and the peer is authenticated by
// the QUIC handshake that follows anyway. Set PunchConfig.SourcePolicy to
// restrict it.
func (p *Puncher) Respond(ctx context.Context, attemptID string, localAddrs, peerAddrs []netip.AddrPort, meta PunchMetadata, config PunchConfig) (PunchResult, error) {
	return p.run(ctx, attemptID, localAddrs, peerAddrs, meta, config, PunchSourceAny)
}

func (p *Puncher) run(ctx context.Context, attemptID string, localAddrs, peerAddrs []netip.AddrPort, meta PunchMetadata, config PunchConfig, fallbackPolicy PunchSourcePolicy) (PunchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if attemptID == "" {
		return PunchResult{}, fmt.Errorf("%w: id is required", ErrInvalidPunchAttempt)
	}
	plan, err := newPunchPlan(localAddrs, peerAddrs, meta, config, fallbackPolicy, p.conn.LocalAddr())
	if err != nil {
		return PunchResult{}, err
	}
	events, err := p.conn.AddPunchAttempt(attemptID, meta)
	if err != nil {
		return PunchResult{}, err
	}
	defer p.conn.RemovePunchAttempt(attemptID)

	if p.base != nil && p.base.Done() != nil {
		var cancel context.CancelFunc
		ctx, cancel = mergeCancel(ctx, p.base)
		defer cancel()
	}
	return runPunch(ctx, &demuxPunchTransport{conn: p.conn, events: events}, plan)
}

// mergeCancel returns a context cancelled when either input is.
func mergeCancel(ctx, other context.Context) (context.Context, context.CancelFunc) {
	merged, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(other, cancel)
	return merged, func() {
		stop()
		cancel()
	}
}

// demuxPunchTransport takes its inbound packets from the conn's demux, which is
// what lets a punch attempt share the socket with a running QUIC connection.
type demuxPunchTransport struct {
	conn   *PunchPacketConn
	events <-chan PunchPacketEvent
}

func (t *demuxPunchTransport) send(to netip.AddrPort, packetType PunchPacketType, key punchKey) {
	sendPunchPacket(t.conn, to, key, packetType)
}

func (t *demuxPunchTransport) recvUntil(ctx context.Context, deadline time.Time, _ punchKey) (PunchPacketEvent, bool, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case ev := <-t.events:
		return ev, true, nil
	case <-timer.C:
		return PunchPacketEvent{}, false, nil
	case <-ctx.Done():
		return PunchPacketEvent{}, false, nil
	}
}

func randomAttemptID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "punch-" + hex.EncodeToString(buf[:]), nil
}
