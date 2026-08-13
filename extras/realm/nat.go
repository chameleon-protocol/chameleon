package realm

import (
	"math/rand/v2"
	"net/netip"
	"slices"
)

// NATClass describes how a NAT allocates the external port of a socket.
type NATClass int

const (
	// NATClassUnknown means the observations were not conclusive. It is never
	// treated as endpoint-dependent: guessing wrong in that direction wastes
	// packets, guessing wrong in the other direction only skips an optimization.
	NATClassUnknown NATClass = iota
	// NATClassEndpointIndependent ("easy" NAT) keeps one external port per
	// socket no matter what it talks to, so the port a STUN server reports is
	// the port a peer can punch at.
	NATClassEndpointIndependent
	// NATClassEndpointDependent ("hard", classically "symmetric" NAT) allocates
	// a fresh external port per destination, so the port a STUN server reports
	// says nothing about the port a peer would have to punch at.
	NATClassEndpointDependent
)

func (c NATClass) String() string {
	switch c {
	case NATClassEndpointIndependent:
		return "endpoint-independent"
	case NATClassEndpointDependent:
		return "endpoint-dependent"
	default:
		return "unknown"
	}
}

// ClassifyNAT infers the NAT class from reflexive addresses observed by
// different observers (STUN servers, or peers reporting what source address
// they saw).
//
// Two different ports on the same address mean the NAT picked a port per
// destination, which is conclusive. Anything else is not: a single observation
// is consistent with every NAT class, and even several matching observations
// only prove the mapping held for those destinations, so the result is
// NATClassUnknown rather than a guess.
func ClassifyNAT(observed []netip.AddrPort) NATClass {
	ports := make(map[netip.Addr]uint16, len(observed))
	for _, addr := range observed {
		if !addr.IsValid() {
			continue
		}
		ip := addr.Addr().Unmap()
		if port, ok := ports[ip]; ok && port != addr.Port() {
			return NATClassEndpointDependent
		}
		ports[ip] = addr.Port()
	}
	return NATClassUnknown
}

// endpointDependentHosts returns the announced hosts whose port allocation
// looks destination-dependent, i.e. the hosts worth spending probes on. Probing
// is restricted to them so a punch never sprays ports at a host that announced
// a single, predictable address.
func endpointDependentHosts(addrs []netip.AddrPort, force bool) map[netip.Addr][]uint16 {
	byHost := make(map[netip.Addr][]uint16)
	for _, addr := range addrs {
		if !addr.IsValid() || !addr.Addr().Is4() {
			// Port prediction is an IPv4 NAT problem; IPv6 peers are reachable
			// at the port they announce or not at all.
			continue
		}
		ip := addr.Addr().Unmap()
		byHost[ip] = append(byHost[ip], addr.Port())
	}
	for ip, ports := range byHost {
		ports = uniqueSortedPorts(ports)
		byHost[ip] = ports
		if len(ports) < 2 && !force {
			delete(byHost, ip)
		}
	}
	return byHost
}

// symmetricNATProbes returns the ports to guess on an endpoint-dependent peer,
// ordered by expected yield: the caller paces them and may never reach the end
// of the list, so the cheap, high-probability guesses have to come first.
//
//  1. Neighbours of the announced ports. NATs that allocate sequentially (a
//     large share of the deployed ones) put the next mapping right next to the
//     one STUN reported.
//  2. The announced stride extrapolated forward. A peer that announced ports
//     n, n+d, n+2d is walking its port space at a fixed step.
//  3. Uniform random ports. This is the birthday-paradox tier and the only one
//     that helps against a NAT that randomizes; see the package documentation
//     for what it is actually worth.
func symmetricNATProbes(peerAddrs []netip.AddrPort, limit int, force bool) []netip.AddrPort {
	if limit <= 0 {
		return nil
	}
	hosts := endpointDependentHosts(peerAddrs, force)
	if len(hosts) == 0 {
		return nil
	}
	ips := make([]netip.Addr, 0, len(hosts))
	for ip := range hosts {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })

	seen := make(map[netip.AddrPort]struct{}, limit)
	for _, addr := range peerAddrs {
		seen[netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())] = struct{}{}
	}
	probes := make([]netip.AddrPort, 0, limit)
	add := func(ip netip.Addr, port int) bool {
		if len(probes) >= limit {
			return false
		}
		if port < symmetricNATMinProbePort || port > 65535 {
			return true
		}
		addr := netip.AddrPortFrom(ip, uint16(port))
		if _, ok := seen[addr]; ok {
			return true
		}
		seen[addr] = struct{}{}
		probes = append(probes, addr)
		return true
	}

	// Tier 1: interleave the hosts so one host with many announced ports cannot
	// use up the whole budget before another host gets a single probe.
tier1:
	for offset := 1; offset <= symmetricNATSequentialSpan; offset++ {
		for _, ip := range ips {
			for _, port := range hosts[ip] {
				if !add(ip, int(port)+offset) || !add(ip, int(port)-offset) {
					break tier1
				}
			}
		}
	}
	// Tier 2: extrapolate a constant stride.
	for _, ip := range ips {
		ports := hosts[ip]
		stride, ok := portStride(ports)
		if !ok {
			continue
		}
		last := int(ports[len(ports)-1])
		for i := 1; i <= symmetricNATStrideProbes; i++ {
			if !add(ip, last+stride*i) {
				break
			}
		}
	}
	// Tier 3: uniform random guesses, spread evenly over the hosts. A draw that
	// repeats an earlier port is simply redrawn; only a long run of repeats,
	// which means the port space is nearly used up, ends the tier.
	misses := 0
	for len(probes) < limit && misses < symmetricNATProbeMissLimit {
		before := len(probes)
		for _, ip := range ips {
			if !add(ip, randomProbePort()) {
				break
			}
		}
		if len(probes) == before {
			misses++
			continue
		}
		misses = 0
	}
	return probes
}

func portStride(ports []uint16) (int, bool) {
	if len(ports) < 2 {
		return 0, false
	}
	stride := int(ports[1]) - int(ports[0])
	if stride <= 0 {
		return 0, false
	}
	for i := 2; i < len(ports); i++ {
		if int(ports[i])-int(ports[i-1]) != stride {
			return 0, false
		}
	}
	return stride, true
}

func randomProbePort() int {
	return symmetricNATMinProbePort + rand.IntN(65536-symmetricNATMinProbePort)
}

func uniqueSortedPorts(ports []uint16) []uint16 {
	slices.Sort(ports)
	return slices.Compact(ports)
}
