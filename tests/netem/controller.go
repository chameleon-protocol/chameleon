package netem

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Controller holds the profile shared by every Conn it creates.
//
// A profile change takes effect on the next datagram, on connections that
// already exist as well as ones created later. That is what makes failover
// measurable: a client that reconnects after its link went dark builds a fresh
// socket, and the fresh socket must be impaired the same way the old one was.
type Controller struct {
	profile atomic.Pointer[Profile]
	seed    uint64
	nextID  atomic.Uint64

	// overrides is copy-on-write so that the per-datagram lookup takes no lock.
	// nOverrides is read first and lets the case with no per-candidate rules --
	// every test that predates them -- skip the map entirely.
	overrides  atomic.Pointer[map[netip.AddrPort]Profile]
	nOverrides atomic.Int64

	mu         sync.Mutex
	live       map[*Conn]struct{}
	retired    Stats
	retiredFor map[netip.AddrPort]Stats
}

// NewController returns a Controller serving the given profile.
func NewController(p Profile) *Controller {
	c := &Controller{live: make(map[*Conn]struct{})}
	c.profile.Store(&p)
	return c
}

// SetSeed makes the loss and jitter draws reproducible across runs. Conns
// created afterwards derive their streams from it. Without it the draws are
// still deterministic per Conn index, seeded from zero.
func (c *Controller) SetSeed(seed uint64) { c.seed = seed }

// Profile returns the profile currently in force.
func (c *Controller) Profile() Profile { return *c.profile.Load() }

// Set replaces the profile.
func (c *Controller) Set(p Profile) { c.profile.Store(&p) }

// SetBlackhole turns total packet loss on or off without disturbing the rest of
// the profile, so a test can cut the link and restore exactly the conditions it
// had before.
func (c *Controller) SetBlackhole(on bool) {
	p := c.Profile()
	c.Set(p.WithBlackhole(on))
}

// SetFor overrides the default profile for one candidate -- one peer address.
// It is what makes a multi-candidate failover measurable: the test kills one
// candidate and leaves the others alone, which is the whole scenario. Without
// it every datagram a Conn carries gets the same treatment and "switch to the
// leg that still works" cannot even be stated.
//
// A candidate under SetFor also gets counters of its own, readable through
// StatsFor. That is the other half of the assertion: the profile says which leg
// was supposed to die, the counters say which leg the traffic actually went to.
//
// Naming a candidate with the default profile is therefore a meaningful call --
// it buys separate counters for a leg the test does not want to impair.
//
// The change takes effect on the next datagram, on Conns that already exist as
// well as ones created later, exactly like Set.
func (c *Controller) SetFor(peer netip.AddrPort, p Profile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[netip.AddrPort]Profile)
	if cur := c.overrides.Load(); cur != nil {
		for k, v := range *cur {
			next[k] = v
		}
	}
	next[peer] = p
	c.overrides.Store(&next)
	c.nOverrides.Store(int64(len(next)))
}

// ClearFor puts a candidate back on the default profile.
//
// It does not undo the split: a Conn that has already given the candidate pipes
// of its own keeps them, so StatsFor goes on counting and the candidate's
// datagrams go on queueing separately from everyone else's. Only the impairment
// reverts.
func (c *Controller) ClearFor(peer netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.overrides.Load()
	if cur == nil {
		return
	}
	if _, ok := (*cur)[peer]; !ok {
		return
	}
	next := make(map[netip.AddrPort]Profile, len(*cur)-1)
	for k, v := range *cur {
		if k != peer {
			next[k] = v
		}
	}
	c.overrides.Store(&next)
	c.nOverrides.Store(int64(len(next)))
}

// ProfileFor returns the profile in force for one candidate: its own if SetFor
// named it, the default otherwise.
func (c *Controller) ProfileFor(peer netip.AddrPort) Profile {
	if m := c.overrides.Load(); m != nil {
		if p, ok := (*m)[peer]; ok {
			return p
		}
	}
	return c.Profile()
}

// StatsFor sums what crossed every Conn the controller has made, to and from
// one candidate. It is zero for a candidate SetFor never named, because a Conn
// only counts separately what it routes separately.
func (c *Controller) StatsFor(peer netip.AddrPort) Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := c.retiredFor[peer]
	for conn := range c.live {
		total = total.add(conn.StatsFor(peer))
	}
	return total
}

func (c *Controller) hasOverrides() bool { return c.nOverrides.Load() != 0 }

func (c *Controller) tracked(peer netip.AddrPort) bool {
	m := c.overrides.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[peer]
	return ok
}

// Wrap puts inner behind the controller's link. The returned Conn owns inner.
func (c *Controller) Wrap(inner net.PacketConn) *Conn {
	id := c.nextID.Add(1)
	conn := newConn(inner, c, c.seed, id*2)
	c.mu.Lock()
	c.live[conn] = struct{}{}
	c.mu.Unlock()
	return conn
}

func (c *Controller) retire(conn *Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.live[conn]; !ok {
		return
	}
	delete(c.live, conn)
	c.retired = c.retired.add(conn.Stats())
	for peer, s := range conn.peerStats() {
		if c.retiredFor == nil {
			c.retiredFor = make(map[netip.AddrPort]Stats)
		}
		c.retiredFor[peer] = c.retiredFor[peer].add(s)
	}
}

// Stats sums the counters of every Conn the controller has created, including
// the ones already closed, so a reconnect does not reset the numbers.
func (c *Controller) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := c.retired
	for conn := range c.live {
		total = total.add(conn.Stats())
	}
	return total
}

// ConnFactory adapts a Controller to the core client's ConnFactory interface,
// so every socket the client creates -- including the ones it creates when
// reconnecting -- crosses the same impaired link.
type ConnFactory struct {
	*Controller
}

func (f ConnFactory) New(net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return f.Wrap(pc), nil
}
