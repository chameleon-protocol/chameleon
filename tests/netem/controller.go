// chameleon -- a censorship-resistant transport
// Copyright (C) 2026 The chameleon authors
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 3 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package netem

import (
	"net"
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

	mu      sync.Mutex
	live    map[*Conn]struct{}
	retired Stats
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
