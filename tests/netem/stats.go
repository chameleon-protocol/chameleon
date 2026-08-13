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
	"fmt"
	"sync/atomic"
)

type dirCounters struct {
	in           atomic.Uint64
	inBytes      atomic.Uint64
	out          atomic.Uint64
	outBytes     atomic.Uint64
	dropped      atomic.Uint64
	droppedBytes atomic.Uint64
}

func (c *dirCounters) snapshot() DirStats {
	return DirStats{
		In:           c.in.Load(),
		InBytes:      c.inBytes.Load(),
		Out:          c.out.Load(),
		OutBytes:     c.outBytes.Load(),
		Dropped:      c.dropped.Load(),
		DroppedBytes: c.droppedBytes.Load(),
	}
}

type counters struct {
	up, down dirCounters
}

// DirStats is what crossed one direction of a link.
type DirStats struct {
	In           uint64 // datagrams offered to the link
	InBytes      uint64
	Out          uint64 // datagrams the link delivered
	OutBytes     uint64
	Dropped      uint64 // lost to Loss, Blackhole or queue overflow
	DroppedBytes uint64
}

// LossRate is the fraction of offered datagrams the link dropped. It is the
// number to assert on when checking that impairment was actually applied --
// the configured Loss is only the expectation of this.
func (d DirStats) LossRate() float64 {
	if d.In == 0 {
		return 0
	}
	return float64(d.Dropped) / float64(d.In)
}

func (d DirStats) add(o DirStats) DirStats {
	return DirStats{
		In:           d.In + o.In,
		InBytes:      d.InBytes + o.InBytes,
		Out:          d.Out + o.Out,
		OutBytes:     d.OutBytes + o.OutBytes,
		Dropped:      d.Dropped + o.Dropped,
		DroppedBytes: d.DroppedBytes + o.DroppedBytes,
	}
}

func (d DirStats) String() string {
	return fmt.Sprintf("in=%d(%dB) out=%d(%dB) dropped=%d(%.2f%%)",
		d.In, d.InBytes, d.Out, d.OutBytes, d.Dropped, d.LossRate()*100)
}

// Stats is what crossed a Conn, or every Conn of a Controller.
type Stats struct {
	Up   DirStats
	Down DirStats
	// Overflow counts datagrams the link delivered but the application was too
	// slow to read. They are indistinguishable from loss to the peer, but they
	// are the harness's fault rather than the profile's, so they are counted
	// apart: a test whose result depends on Overflow is measuring the harness.
	Overflow uint64
}

func (s Stats) add(o Stats) Stats {
	return Stats{
		Up:       s.Up.add(o.Up),
		Down:     s.Down.add(o.Down),
		Overflow: s.Overflow + o.Overflow,
	}
}

func (s Stats) String() string {
	return fmt.Sprintf("up{%s} down{%s} overflow=%d", s.Up, s.Down, s.Overflow)
}
