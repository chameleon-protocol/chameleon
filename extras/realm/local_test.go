package realm

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInterface(name string, flags net.Flags, addrs ...string) Interface {
	iface := Interface{Name: name, Flags: flags}
	for _, s := range addrs {
		iface.Addrs = append(iface.Addrs, netip.MustParseAddr(s))
	}
	return iface
}

const up = net.FlagUp

func TestLocalCandidatesSkipsLoopback(t *testing.T) {
	ifaces := []Interface{
		testInterface("lo0", up|net.FlagLoopback, "127.0.0.1", "::1"),
		// A loopback address on a non-loopback interface still must not be
		// announced: no peer can reach it.
		testInterface("eth0", up, "192.168.1.10", "127.0.0.2"),
	}
	got := LocalCandidatesFrom(ifaces, 4433, AddrFamilyAny)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:4433")}, got)
}

func TestLocalCandidatesSkipsDownInterfaces(t *testing.T) {
	ifaces := []Interface{
		testInterface("eth0", 0, "192.168.1.10"),
		testInterface("wlan0", up, "192.168.1.11"),
	}
	got := LocalCandidatesFrom(ifaces, 4433, AddrFamilyAny)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("192.168.1.11:4433")}, got)
}

func TestLocalCandidatesPrefersIPv6(t *testing.T) {
	ifaces := []Interface{
		testInterface("eth0", up, "192.168.1.10", "2001:db8::2"),
		testInterface("eth1", up, "10.0.0.5", "fd00::1"),
	}
	got := LocalCandidatesFrom(ifaces, 4433, AddrFamilyAny)
	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::2]:4433"),
		netip.MustParseAddrPort("[fd00::1]:4433"),
		netip.MustParseAddrPort("10.0.0.5:4433"),
		netip.MustParseAddrPort("192.168.1.10:4433"),
	}, got)
}

func TestLocalCandidatesDropsIPv6LinkLocal(t *testing.T) {
	ifaces := []Interface{
		testInterface("eth0", up, "fe80::1", "192.168.1.10"),
	}
	got := LocalCandidatesFrom(ifaces, 4433, AddrFamilyAny)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:4433")}, got)

	// Even with nothing else to announce, an fe80:: candidate is not usable
	// by a peer, so it is never the fallback.
	only := LocalCandidatesFrom([]Interface{testInterface("eth0", up, "fe80::1")}, 4433, AddrFamilyAny)
	assert.Empty(t, only)
}

func TestLocalCandidatesIPv4LinkLocalIsLastResort(t *testing.T) {
	withRoutable := LocalCandidatesFrom([]Interface{
		testInterface("eth0", up, "169.254.7.7", "192.168.1.10"),
	}, 4433, AddrFamilyAny)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:4433")}, withRoutable)

	onlyLinkLocal := LocalCandidatesFrom([]Interface{
		testInterface("eth0", up, "169.254.7.7"),
	}, 4433, AddrFamilyAny)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("169.254.7.7:4433")}, onlyLinkLocal)
}

func TestLocalCandidatesFamilyRestriction(t *testing.T) {
	ifaces := []Interface{testInterface("eth0", up, "192.168.1.10", "2001:db8::2")}
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:4433")},
		LocalCandidatesFrom(ifaces, 4433, AddrFamilyIPv4))
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::2]:4433")},
		LocalCandidatesFrom(ifaces, 4433, AddrFamilyIPv6))
}

func TestLocalCandidatesDeduplicatesAndCaps(t *testing.T) {
	ifaces := []Interface{
		testInterface("eth0", up, "192.168.1.10"),
		testInterface("eth0:1", up, "192.168.1.10"),
	}
	assert.Len(t, LocalCandidatesFrom(ifaces, 4433, AddrFamilyAny), 1)

	var many []Interface
	for i := 0; i < 20; i++ {
		many = append(many, testInterface("br", up, netip.AddrFrom4([4]byte{172, 17, byte(i), 1}).String()))
	}
	assert.Len(t, LocalCandidatesFrom(many, 4433, AddrFamilyAny), maxLocalCandidates)
}

// A host with a long list of IPv6 addresses (temporary and stable ones per
// interface, plus every VPN and container bridge) must not push the IPv4 LAN
// address out of the announcement: on a v4-only LAN it is the only candidate
// the peer can use.
func TestLocalCandidatesCapKeepsBothFamilies(t *testing.T) {
	ifaces := []Interface{testInterface("eth0", up, "192.168.1.10", "192.168.1.11")}
	for i := 0; i < 10; i++ {
		ifaces = append(ifaces, testInterface("utun", up,
			netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i + 1)}).String()))
	}
	got := LocalCandidatesFrom(ifaces, 4433, AddrFamilyAny)
	assert.Len(t, got, maxLocalCandidates)
	assert.Contains(t, got, netip.MustParseAddrPort("192.168.1.10:4433"))
	assert.Contains(t, got, netip.MustParseAddrPort("192.168.1.11:4433"))
	// IPv6 still leads, and takes every slot IPv4 does not need.
	assert.True(t, got[0].Addr().Is6())
	assert.Len(t, slices.DeleteFunc(slices.Clone(got), func(a netip.AddrPort) bool { return a.Addr().Is4() }),
		maxLocalCandidates-2)
}

func TestLocalCandidatesWithoutPort(t *testing.T) {
	ifaces := []Interface{testInterface("eth0", up, "192.168.1.10")}
	assert.Empty(t, LocalCandidatesFrom(ifaces, 0, AddrFamilyAny))
}

func TestHostInterfacesYieldsNoLoopbackCandidates(t *testing.T) {
	addrs, err := LocalCandidates(4433, AddrFamilyAny)
	require.NoError(t, err)
	for _, addr := range addrs {
		assert.False(t, addr.Addr().IsLoopback(), "loopback candidate announced: %s", addr)
		assert.False(t, addr.Addr().Is4In6(), "candidate not unmapped: %s", addr)
		assert.Equal(t, uint16(4433), addr.Port())
	}
}

func TestMergeCandidatesOrdersLocalFirst(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:4433")}
	reflexive := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:51820")}
	assert.Equal(t, []netip.AddrPort{local[0], reflexive[0]}, MergeCandidates(local, reflexive))
}

func TestMergeCandidatesPutsIPv6FirstInEachTier(t *testing.T) {
	local := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.10:4433"),
		netip.MustParseAddrPort("[fd00::1]:4433"),
	}
	reflexive := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.5:51820"),
		netip.MustParseAddrPort("[2001:db8::5]:51820"),
	}
	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("[fd00::1]:4433"),
		netip.MustParseAddrPort("192.168.1.10:4433"),
		netip.MustParseAddrPort("[2001:db8::5]:51820"),
		netip.MustParseAddrPort("198.51.100.5:51820"),
	}, MergeCandidates(local, reflexive))
}

func TestMergeCandidatesUnmapsIPv4In6(t *testing.T) {
	mapped := netip.AddrPortFrom(netip.MustParseAddr("::ffff:192.168.1.10"), 4433)
	got := MergeCandidates([]netip.AddrPort{mapped}, nil)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:4433")}, got)
}

func TestMergeCandidatesKeepsLocalCopyOfDuplicate(t *testing.T) {
	// A host with no NAT sees its own address reflected back by STUN. It must
	// appear once, in the local tier, so it survives the peer's candidate cap.
	shared := netip.MustParseAddrPort("203.0.113.5:4433")
	other := netip.MustParseAddrPort("203.0.113.9:4433")
	got := MergeCandidates([]netip.AddrPort{shared}, []netip.AddrPort{other, shared})
	assert.Equal(t, []netip.AddrPort{shared, other}, got)
}

func TestMergeCandidatesDropsUnusable(t *testing.T) {
	got := MergeCandidates(
		[]netip.AddrPort{{}, netip.AddrPortFrom(netip.MustParseAddr("192.168.1.10"), 0)},
		[]netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:4433")},
	)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:4433")}, got)
}

// Two peers on the same LAN must end up in each other's candidate set, and
// the initiator's source filter must accept the LAN address the other one
// actually punches from. Before local enumeration this failed twice over: the
// LAN address was never announced, and a packet arriving from it was dropped
// as an unknown source.
func TestSameLANPeersAcceptEachOther(t *testing.T) {
	const port = 4433
	serverIfaces := []Interface{testInterface("eth0", up, "192.168.1.10", "2001:db8::10")}
	clientIfaces := []Interface{testInterface("wlan0", up, "192.168.1.20", "2001:db8::20")}

	serverAddrs := MergeCandidates(
		LocalCandidatesFrom(serverIfaces, port, AddrFamilyAny),
		[]netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:40000")},
	)
	clientAddrs := MergeCandidates(
		LocalCandidatesFrom(clientIfaces, port, AddrFamilyAny),
		[]netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:40001")},
	)

	serverLAN := netip.MustParseAddrPort("192.168.1.10:4433")
	clientLAN := netip.MustParseAddrPort("192.168.1.20:4433")
	assert.Contains(t, serverAddrs, serverLAN)
	assert.Contains(t, clientAddrs, clientLAN)

	// Client side: the server's announced addresses are the peer set.
	clientCandidates := candidatePunchAddrs(clientAddrs, serverAddrs, AddrFamilyAny)
	clientFilter := newPunchSourceFilter(clientCandidates, PunchSourceCandidates)
	assert.True(t, clientFilter.allows(serverLAN), "client rejects the server's LAN source")
	assert.True(t, clientFilter.allows(netip.MustParseAddrPort("[2001:db8::10]:4433")))
	assert.False(t, clientFilter.allows(netip.MustParseAddrPort("198.51.100.1:4433")))

	// Server side, with the strict policy a caller may opt into.
	serverCandidates := candidatePunchAddrs(serverAddrs, clientAddrs, AddrFamilyAny)
	serverFilter := newPunchSourceFilter(serverCandidates, PunchSourceCandidates)
	assert.True(t, serverFilter.allows(clientLAN), "server rejects the client's LAN source")
}

// The peer keeps only maxPunchPeerAddrs of the announced list, so the LAN
// addresses have to be at the front to survive a host with many interfaces.
func TestLocalCandidatesSurvivePeerAddrCap(t *testing.T) {
	const port = 4433
	local := LocalCandidatesFrom([]Interface{
		testInterface("eth0", up, "192.168.1.10"),
	}, port, AddrFamilyAny)
	reflexive := make([]netip.AddrPort, 0, maxPunchPeerAddrs*2)
	for i := 0; i < maxPunchPeerAddrs*2; i++ {
		reflexive = append(reflexive, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}), port))
	}
	announced := MergeCandidates(local, reflexive)
	require.Greater(t, len(announced), maxPunchPeerAddrs)

	candidates := candidatePunchAddrs(nil, announced, AddrFamilyAny)
	assert.Contains(t, candidates, netip.MustParseAddrPort("192.168.1.10:4433"))
}
