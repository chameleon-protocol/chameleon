package netem

import (
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/netip"
)

// A candidate is identified here by its peer address: the destination of a
// datagram on the way up, the source of one on the way down.
//
// The alternatives were considered and rejected. The local socket cannot name a
// candidate: one client socket reaches every candidate at once, and the socket
// is thrown away and rebuilt on every reconnect, so a rule attached to it does
// not survive the event the rules exist to describe. A synthetic candidate index
// would have to be threaded through net.PacketConn, which has no room for it.
// The peer address is the only thing that is present, symmetrically, at both
// ends of the interface this layer implements -- WriteTo takes it, ReadFrom
// returns it -- and it is also the thing a Selector actually chooses between, so
// a test and the code under test are naming the same object.
//
// The consequence to keep in mind: two candidates that differ only in something
// this layer cannot see (the same server address reached over two local
// interfaces, say) are one candidate here.

// PeerKey reduces a net.Addr to the key a per-candidate rule is stored under.
// It reports false for an address that has no IP and port, which cannot name a
// candidate.
//
// IPv4-mapped IPv6 addresses are unmapped, because a dual-stack socket reports
// ::ffff:127.0.0.1 for a peer a test spelled 127.0.0.1 and the two have to land
// on the same rule.
func PeerKey(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case nil:
		return netip.AddrPort{}, false
	case *net.UDPAddr:
		ap := v.AddrPort()
		k := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		return k, k.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	k := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	return k, k.IsValid()
}

// peerLink is one candidate's own pair of pipes inside a Conn.
//
// A candidate gets its own pipes rather than a shared one with a per-datagram
// profile lookup because a pipe is also a queue: two candidates behind one queue
// would make a datagram held up on the slow one delay a datagram on the fast
// one, which is the opposite of what separate paths mean.
type peerLink struct {
	up, down *pipe
	counters counters
}

func (c *Conn) peerFor(addr net.Addr) *peerLink {
	// The common case is a Conn with no per-candidate rules at all, and it must
	// stay a straight line: no lock, no map, no address parsing. nPeers keeps a
	// candidate on its own pipes after ClearFor drops the last rule, so its
	// counters do not stop mid-experiment.
	if c.nPeers.Load() == 0 && (c.ctrl == nil || !c.ctrl.hasOverrides()) {
		return nil
	}
	key, ok := PeerKey(addr)
	if !ok {
		return nil
	}
	c.peersMu.RLock()
	pl := c.peers[key]
	c.peersMu.RUnlock()
	if pl != nil {
		return pl
	}
	if !c.ctrl.tracked(key) {
		return nil
	}
	return c.newPeerLink(key)
}

func (c *Conn) newPeerLink(key netip.AddrPort) *peerLink {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	if pl := c.peers[key]; pl != nil {
		return pl
	}
	select {
	case <-c.closed:
		// Close has already stopped the pipes it knew about; a link made now
		// would leak its goroutines. The default pipes are stopped too, so the
		// datagram is going nowhere either way.
		return nil
	default:
	}
	pl := &peerLink{}
	// Derive this candidate's draw streams from the Conn's seeds and the address,
	// so a run is reproducible and adding a candidate does not shift the loss
	// pattern of the ones already there.
	h := peerSeed(key)
	ctrl := c.ctrl
	pl.up = newPipe(func() Link { return ctrl.ProfileFor(key).Up }, c.sendUp, &pl.counters.up,
		true, rand.New(rand.NewPCG(c.seed1^h, c.seed2^h)))
	pl.down = newPipe(func() Link { return ctrl.ProfileFor(key).Down }, c.deliverDown, &pl.counters.down,
		false, rand.New(rand.NewPCG(c.seed1^h, c.seed2^h+1)))
	if c.peers == nil {
		c.peers = make(map[netip.AddrPort]*peerLink)
	}
	c.peers[key] = pl
	c.nPeers.Store(int64(len(c.peers)))
	return pl
}

// peerSeed hashes a candidate's address into a seed offset. It is FNV-1a rather
// than maphash because maphash is seeded per process, and a draw stream that
// changes from run to run would take reproducibility away from exactly the
// tests that need it most.
func peerSeed(key netip.AddrPort) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key.String()))
	return h.Sum64()
}

// StatsFor returns what crossed this Conn to and from one candidate. It is zero
// for a candidate the Conn never gave its own pipes to -- that traffic is in
// Stats instead, indistinguishable from every other peer's.
//
// Overflow is a property of the Conn's single receive queue, not of a
// candidate, so it is always zero here.
func (c *Conn) StatsFor(key netip.AddrPort) Stats {
	c.peersMu.RLock()
	pl := c.peers[key]
	c.peersMu.RUnlock()
	if pl == nil {
		return Stats{}
	}
	return Stats{Up: pl.counters.up.snapshot(), Down: pl.counters.down.snapshot()}
}

// peerStats returns every candidate's counters, for the Conn's own total and
// for the Controller to bank when the Conn closes.
func (c *Conn) peerStats() map[netip.AddrPort]Stats {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()
	if len(c.peers) == 0 {
		return nil
	}
	out := make(map[netip.AddrPort]Stats, len(c.peers))
	for key, pl := range c.peers {
		out[key] = Stats{Up: pl.counters.up.snapshot(), Down: pl.counters.down.snapshot()}
	}
	return out
}

func (c *Conn) stopPeers() {
	c.peersMu.Lock()
	links := make([]*peerLink, 0, len(c.peers))
	for _, pl := range c.peers {
		links = append(links, pl)
	}
	c.peersMu.Unlock()
	for _, pl := range links {
		pl.up.stop()
		pl.down.stop()
	}
}
