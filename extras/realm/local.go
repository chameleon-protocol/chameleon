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

package realm

import (
	"net"
	"net/netip"
	"slices"
	"strings"
)

// A host can have a long tail of interfaces (containers, VPNs, virtual
// bridges), and the peer only keeps maxPunchPeerAddrs of what we announce.
// Cap the local set so a machine with a dozen bridges cannot crowd out the
// reflexive addresses that are the only hope of reaching it from outside.
const maxLocalCandidates = 8

// Interface is the subset of net.Interface that candidate gathering needs.
// It exists so tests can inject an interface list without the host's real
// network configuration leaking into the assertions.
type Interface struct {
	Name  string
	Flags net.Flags
	Addrs []netip.Addr
}

// HostInterfaces enumerates the machine's interfaces.
func HostInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		entry := Interface{Name: iface.Name, Flags: iface.Flags}
		addrs, err := iface.Addrs()
		if err != nil {
			// A single interface disappearing mid-enumeration (common on
			// laptops) must not cost us every other candidate.
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			// net.IPNet keeps IPv4 in 4-in-6 form half the time; unmap here so
			// candidates compare equal to the addresses punch packets arrive
			// from, which are unmapped too (see addrToAddrPort).
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			entry.Addrs = append(entry.Addrs, ip.Unmap())
		}
		out = append(out, entry)
	}
	return out, nil
}

// LocalCandidates returns the host's own addresses paired with port, for a
// socket bound to the wildcard address on that port.
//
// Without these, two peers on the same LAN only ever learn each other's
// reflexive (STUN) addresses and have to reach each other by NAT hairpin —
// which many home routers do not implement at all, and the rest do by sending
// every packet out to the gateway and back.
func LocalCandidates(port uint16, family AddrFamily) ([]netip.AddrPort, error) {
	ifaces, err := HostInterfaces()
	if err != nil {
		return nil, err
	}
	return LocalCandidatesFrom(ifaces, port, family), nil
}

// LocalCandidatesFrom builds the local candidate set from an already
// enumerated interface list.
func LocalCandidatesFrom(ifaces []Interface, port uint16, family AddrFamily) []netip.AddrPort {
	if port == 0 {
		return nil
	}
	var routable6, routable4, linkLocal4 []netip.AddrPort
	seen := make(map[netip.AddrPort]struct{})
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		for _, ip := range iface.Addrs {
			ip = ip.Unmap()
			if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if !family.allows(net.IP(ip.AsSlice())) {
				continue
			}
			addr := netip.AddrPortFrom(ip.WithZone(""), port)
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			switch {
			case ip.Is4() && ip.IsLinkLocalUnicast():
				linkLocal4 = append(linkLocal4, addr)
			case ip.Is6() && ip.IsLinkLocalUnicast():
				// IPv6 link-local is dropped rather than kept as a last
				// resort. A zoneless fe80:: address cannot be sent to at all,
				// and a zoned one fails twice over: the zone names an
				// interface on the announcing host, which means nothing to the
				// peer, and the punch source filter compares whole AddrPorts,
				// so an inbound packet (carrying the receiver's zone) would
				// never match the announced candidate anyway.
				continue
			case ip.Is6():
				routable6 = append(routable6, addr)
			default:
				routable4 = append(routable4, addr)
			}
		}
	}
	out := capLocalCandidates(orderCandidates(routable6), orderCandidates(routable4))
	if len(out) == 0 {
		// An APIPA address is only useful when nothing else was configured,
		// e.g. a link with no DHCP server. Then it is the LAN.
		out = capLocalCandidates(nil, orderCandidates(linkLocal4))
	}
	return out
}

// capLocalCandidates trims the local set to maxLocalCandidates, keeping the
// IPv6 addresses in front but guaranteeing each family half the budget before
// either may spill into the other's unused slots.
//
// A plain "IPv6 first, then truncate" would starve IPv4 on hosts that are not
// unusual at all: macOS keeps a temporary and a stable IPv6 address per
// interface, and every VPN or container bridge adds more. Eight of those would
// push out the IPv4 LAN address, which on a v4-only LAN is the only candidate
// the peer can actually use.
func capLocalCandidates(v6, v4 []netip.AddrPort) []netip.AddrPort {
	if len(v6)+len(v4) <= maxLocalCandidates {
		return slices.Concat(v6, v4)
	}
	share := maxLocalCandidates / 2
	take6 := min(len(v6), share)
	take4 := min(len(v4), share)
	spare := maxLocalCandidates - take6 - take4
	if extra := min(spare, len(v6)-take6); extra > 0 {
		take6 += extra
		spare -= extra
	}
	if extra := min(spare, len(v4)-take4); extra > 0 {
		take4 += extra
	}
	return slices.Concat(v6[:take6], v4[:take4])
}

// MergeCandidates joins locally enumerated addresses with reflexive ones
// (STUN, gateway port mapping), dropping duplicates.
//
// Local addresses come first, and that order is load-bearing: the peer keeps
// only the first maxPunchPeerAddrs addresses it is told about. It punches all
// of them in parallel afterwards, so the order it sends in does not matter —
// the lowest-RTT path answers first regardless — but an address that fell off
// the end of the announcement is never punched at all. A same-LAN path is both
// the cheapest one available and the one most at risk of being truncated,
// since a host can have several interfaces while STUN yields one or two
// addresses, so it goes at the front.
func MergeCandidates(local, reflexive []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(local)+len(reflexive))
	seen := make(map[netip.AddrPort]struct{}, len(local)+len(reflexive))
	for _, addrs := range [][]netip.AddrPort{local, reflexive} {
		for _, addr := range orderCandidates(addrs) {
			if !addr.IsValid() || addr.Port() == 0 {
				continue
			}
			// Keeping the first occurrence means a reflexive address that
			// turns out to be one of ours (no NAT at all) stays in the local
			// tier instead of sinking to the back of the list.
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out
}

// orderCandidates normalizes a tier of candidates and puts IPv6 ahead of
// IPv4: an IPv6 address is usually globally routable with no NAT in front of
// it, so it is the one most likely to give a direct path. Within a family the
// order is by string form, which keeps the announced list stable across
// gathering rounds — callers compare successive lists to decide whether to
// republish them.
func orderCandidates(addrs []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, addr := range addrs {
		// Unmap so a candidate compares equal to the address punch packets
		// arrive from, which is unmapped too (see addrToAddrPort). Zones only
		// mean something on the host that owns the interface, so they are not
		// announced.
		out = append(out, netip.AddrPortFrom(addr.Addr().Unmap().WithZone(""), addr.Port()))
	}
	slices.SortStableFunc(out, func(a, b netip.AddrPort) int {
		if a.Addr().Is4() != b.Addr().Is4() {
			if a.Addr().Is4() {
				return 1
			}
			return -1
		}
		return strings.Compare(a.String(), b.String())
	})
	return out
}
