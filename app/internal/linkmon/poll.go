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

package linkmon

import (
	"context"
	"net"
	"slices"
	"sort"
)

// ifaceState is the part of an interface's state a change would move. Keyed
// by name; the index is carried too because a name can be reused by a
// different interface (a tunnel torn down and recreated), which is a link
// change even though the name never disappeared from the list.
type ifaceState struct {
	index int
	up    bool
	addrs []string
}

// enumerateInterfaces takes a snapshot of every interface and its addresses.
//
// A failure anywhere aborts the whole snapshot rather than returning a
// partial one. A partial snapshot is worse than none: the interfaces missing
// from it would diff as removed, and the poller would report a link change
// that never happened, every round, forever.
func enumerateInterfaces() (map[string]ifaceState, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make(map[string]ifaceState, len(ifis))
	for _, ifi := range ifis {
		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, err
		}
		strs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			strs = append(strs, a.String())
		}
		// The kernel's order is not a promise, and a reordering is not a
		// change.
		sort.Strings(strs)
		out[ifi.Name] = ifaceState{
			index: ifi.Index,
			// Up on its own is not enough. A WiFi adapter that has lost its
			// association stays administratively up; FlagRunning is the bit
			// that moves when the link goes away underneath us.
			up:    ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagRunning != 0,
			addrs: strs,
		}
	}
	return out, nil
}

func diffStates(prev, cur map[string]ifaceState) Change {
	var c Change
	for name, cs := range cur {
		ps, ok := prev[name]
		if !ok || ps.index != cs.index || ps.up != cs.up {
			c |= ChangeLink
		}
		if !slices.Equal(ps.addrs, cs.addrs) {
			c |= ChangeAddr
		}
	}
	for name := range prev {
		if _, ok := cur[name]; !ok {
			c |= ChangeLink
		}
	}
	return c
}

// poll is the fallback notification source: enumerate, diff against the last
// snapshot, report what moved. It runs until ctx is done.
func (m *Monitor) poll(ctx context.Context, raw chan<- Change) {
	prev, err := m.enumerate()
	have := err == nil
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.after(m.cfg.PollInterval):
		}
		cur, err := m.enumerate()
		if err != nil {
			// Keep the last good snapshot and try again next round. Diffing
			// against a snapshot we could not take would invent changes.
			continue
		}
		if !have {
			prev, have = cur, true
			continue
		}
		c := diffStates(prev, cur)
		prev = cur
		if c == 0 {
			continue
		}
		select {
		case raw <- c:
		case <-ctx.Done():
			return
		}
	}
}
