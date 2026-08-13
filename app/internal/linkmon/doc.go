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

// Package linkmon reports when the machine's network attachment changes, so
// that the layer above can re-enumerate its candidate addresses.
//
// The problem it solves: a client that has picked a UDP candidate and is
// happily running QUIC over it has no idea that the laptop lid moved from
// WiFi to cellular. It finds out the slow way — packets stop arriving, loss
// detection fires, and only after several PTOs does anything upstream
// conclude that the path is gone. Meanwhile the new interface has been up and
// usable the whole time. The kernel knew the instant it happened; this
// package is the wire from the kernel to us. The target is that a
// WiFi↔cellular handover leads to a fresh candidate set in under a second,
// which is only achievable by being told, not by discovering.
//
// # What counts as a change
//
// Two kinds, reported as bits in Change: an interface appearing,
// disappearing, or flipping its up/running state (ChangeLink), and an address
// being added to or removed from an interface (ChangeAddr). Consumers are
// expected to treat any event the same way — re-enumerate — so the bits are
// for logging and for deciding how loudly to complain, not for control flow.
//
// Route table changes are deliberately not watched. They are attractive (a
// default route moving from wlan0 to rmnet0 is exactly the event we care
// about) and they are a trap: the route table is the busiest table in the
// kernel. Measured on an idle macOS laptop, two pings to a fresh destination
// produced seven RTM_MISS messages on the route socket; on a router the
// neighbour churn never stops. Treating that as "the network moved" would
// mean re-enumerating candidates for the rest of the process's life. A real
// link switch always moves addresses too, so the quiet signal is sufficient
// and the noisy one buys nothing.
//
// # Coalescing
//
// A handover is never one notification. The old interface loses its address,
// the new one comes up, gets a v4 address, then a v6 address, then a router
// advertisement lands: a dozen notifications over a few hundred
// milliseconds. Reporting each of them would make the consumer re-enumerate
// a dozen times over a network that is still moving. So notifications are
// debounced — held until the burst goes quiet (Config.Debounce), and in any
// case emitted no later than Config.MaxDelay after the burst began, because
// a link that flaps forever must not defer the report forever.
//
// The event channel is buffered for one event and is never allowed to lose
// information: if the consumer has not drained the previous event, the new
// one is merged into it (union of the Change bits, summed Count) rather than
// dropped or blocked on. A consumer that only ever re-enumerates therefore
// cannot miss a change, no matter how slow it is.
//
// # Degradation
//
// Each platform has a native mechanism — netlink on Linux, the PF_ROUTE
// socket on the BSDs, the iphlpapi change callbacks on Windows. Anywhere
// else, and anywhere the native mechanism refuses to start or dies under us,
// the monitor falls back to polling the interface list. Polling cannot meet
// the one-second target and is not meant to; it is the floor. Which
// mechanism is in effect, and why it is not the native one, is reported by
// Monitor.Source — log it at startup, because a monitor that quietly degraded
// to a 2s poll looks exactly like a monitor that works until the day it has
// to be fast.
//
// # Usage
//
//	mon := linkmon.New(linkmon.Config{})
//	events := mon.Watch(ctx)
//	if src, err := mon.Source(); err != nil {
//		logger.Warn("link monitor degraded", zap.String("source", string(src)), zap.Error(err))
//	}
//	for ev := range events {
//		// something moved: throw away the candidate set and build a new one
//	}
//
// The channel is closed when the context is done. Watch may be called once
// per Monitor.
package linkmon
