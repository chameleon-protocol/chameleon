package client

import (
	"errors"
	"net"

	"github.com/chameleon-protocol/chameleon/core/v2/internal/congestion"

	"github.com/chameleon-protocol/quic-go"
)

// ErrNoConnection is returned by a PathController that has no live connection
// to move. A reconnecting client is in that state between attempts, and asking
// it to switch paths must not be the thing that dials one.
var ErrNoConnection = errors.New("no connection to switch")

// PathController moves a live connection from one server address to another
// without tearing it down. It is the whole of what a candidate selector needs
// from the transport, and deliberately nothing more: the selector never sees a
// *quic.Conn, so it cannot reach the parts of a switch that have to happen in
// a fixed order.
//
// It lives in core/client rather than in a package of its own because a switch
// is not just an address change. Putting the connection back on the congestion
// controller the handshake negotiated is the third step of it (see
// clientImpl.SwitchTo), and what that negotiation settled on -- the peer's
// declared receive rate, whether the peer asked for bandwidth detection -- is
// computed inside connect and exists nowhere else. A separate package would
// have to be handed all of it, which is this interface with extra steps and one
// more place for the order to be got wrong.
//
// Obtain one by type-asserting a Client, the same way PathStatsProvider is
// obtained: Client is implemented outside this package, so growing it would
// break every implementation at once.
type PathController interface {
	// SwitchTo points the connection at addr and discards everything it
	// learned from the address it was using.
	SwitchTo(addr net.Addr) error

	// Current is the address the connection is sending to. It is not
	// necessarily the address SwitchTo was last given: with the path manager
	// off, the connection also follows the source address of the packets it
	// accepts, which is how it survives a NAT rebinding.
	Current() net.Addr
}

var (
	_ PathController = (*clientImpl)(nil)
	_ PathController = (*reconnectableClientImpl)(nil)
)

// SwitchTo moves this client's QUIC connection to addr.
//
// Three things have to happen, in this order, and none of them is optional:
//
//  1. The connection's destination changes. On its own this leaves the
//     connection believing everything it measured about the old path.
//
//  2. That belief is discarded -- the RTT estimate, the congestion window, the
//     PTO backoff, the discovered MTU, and the accounting for packets in flight
//     to an address we are no longer talking to. Keeping the old RTT across a
//     switch to a slower path fires the PTO before the first packet on the new
//     path could possibly have been acknowledged, so the connection answers a
//     working path with a burst of spurious retransmissions.
//
//  3. The congestion controller the handshake negotiated is installed again.
//     This is not housekeeping: step 2 replaces the controller with quic-go's
//     default Reno sender, so a switch that stops here silently drops the
//     rate-based controller at the exact moment it is most needed. The order
//     matters in both directions -- installing the controller before the reset
//     means the reset throws it away.
//
// ResetPathState blocks until the reset has run on the connection's own
// goroutine, which is what makes step 3 safe to do from this one.
//
// A switch onto a connection that is already finished reports ErrNoConnection
// rather than success, because a selector calls this on exactly the connection
// it suspects is dead and a false success there is a selector that believes it
// has recovered and stops trying. The liveness of the connection is read from
// its context, which quic-go cancels when the connection closes for any reason
// -- our own Close, the peer's, or the idle timeout. c.conn itself is no help:
// it is assigned once at the end of connect and never cleared, so it is nil
// only before this client has ever had a connection.
//
// The check cannot be raceless -- a connection may die in the instant after it
// -- and it is not trying to be. It removes the case a selector actually meets,
// a connection that has been dead for as long as it took to notice.
func (c *clientImpl) SwitchTo(addr net.Addr) error {
	if addr == nil {
		return errors.New("switch to a nil address")
	}
	// One switch at a time. Two of them interleaved would run step 3 of one
	// against step 2 of the other, and the loser's congestion controller is the
	// default Reno sender rather than anything anybody asked for.
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	if c.conn == nil || c.conn.Context().Err() != nil {
		return ErrNoConnection
	}
	c.conn.SetRemoteAddr(addr)
	c.conn.ResetPathState()
	// ResetPathState returns without resetting anything if the connection died
	// while it was waiting for the run loop (quic-go's connection.go: it selects
	// on the connection's context in both directions). Reporting success then
	// would be the same false success by another door -- step 2 did not happen,
	// so the caller would be told a switch it can rely on had taken place.
	if c.conn.Context().Err() != nil {
		return ErrNoConnection
	}
	c.installCongestionControl(c.conn)
	return nil
}

// Current is the address the connection is sending to.
func (c *clientImpl) Current() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

// installCongestionControl puts the connection on the controller the handshake
// settled on. It runs once when the connection comes up and again after every
// path switch, because resetting the path state replaces the controller.
//
// A txRate of zero means no rate was agreed -- either the server asked for
// bandwidth detection, or neither end declared one -- and the configured
// controller is what handles that case.
func (c *clientImpl) installCongestionControl(conn *quic.Conn) {
	if c.txRate > 0 {
		congestion.UseBrutal(conn, c.txRate, c.config.BandwidthConfig.DisableLossCompensation)
		return
	}
	congestion.UseConfigured(conn, c.config.CongestionConfig.Type, c.config.CongestionConfig.BBRProfile)
}

// SwitchTo moves whichever connection is current. It does not reconnect: a
// selector still trying candidates on a client whose connection has gone would
// otherwise be the thing that dials, which is the reconnect logic's job and
// happens on the next TCP or UDP call.
func (rc *reconnectableClientImpl) SwitchTo(addr net.Addr) error {
	rc.m.Lock()
	client := rc.client
	rc.m.Unlock()

	if p, ok := client.(PathController); ok {
		return p.SwitchTo(addr)
	}
	return ErrNoConnection
}

// Current is the address the connection that happens to be current is sending
// to, or nil when there is none.
func (rc *reconnectableClientImpl) Current() net.Addr {
	rc.m.Lock()
	client := rc.client
	rc.m.Unlock()

	if p, ok := client.(PathController); ok {
		return p.Current()
	}
	return nil
}
