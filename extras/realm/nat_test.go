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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyNAT(t *testing.T) {
	tests := []struct {
		name     string
		observed []netip.AddrPort
		want     NATClass
	}{
		{
			name: "two ports on one address is conclusive",
			observed: []netip.AddrPort{
				netip.MustParseAddrPort("198.51.100.20:40000"),
				netip.MustParseAddrPort("198.51.100.20:51234"),
			},
			want: NATClassEndpointDependent,
		},
		{
			name: "one observation proves nothing",
			observed: []netip.AddrPort{
				netip.MustParseAddrPort("198.51.100.20:40000"),
			},
			want: NATClassUnknown,
		},
		{
			name: "agreeing observations are not proof either",
			observed: []netip.AddrPort{
				netip.MustParseAddrPort("198.51.100.20:40000"),
				netip.MustParseAddrPort("198.51.100.20:40000"),
			},
			want: NATClassUnknown,
		},
		{
			name: "different hosts are not compared",
			observed: []netip.AddrPort{
				netip.MustParseAddrPort("198.51.100.20:40000"),
				netip.MustParseAddrPort("203.0.113.5:51234"),
			},
			want: NATClassUnknown,
		},
		{
			name: "v4-in-v6 is the same host",
			observed: []netip.AddrPort{
				netip.MustParseAddrPort("198.51.100.20:40000"),
				netip.MustParseAddrPort("[::ffff:198.51.100.20]:51234"),
			},
			want: NATClassEndpointDependent,
		},
		{
			name:     "no observations",
			observed: nil,
			want:     NATClassUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ClassifyNAT(tc.observed))
		})
	}
}

// The nearest neighbours of the announced ports come first: a NAT that hands
// out ports sequentially is the case worth spending the first probes on.
func TestSymmetricNATProbesStartAtTheAnnouncedPorts(t *testing.T) {
	announced := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:40003"),
	}

	probes := symmetricNATProbes(announced, 6, false)
	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40001"),
		netip.MustParseAddrPort("198.51.100.20:39999"),
		netip.MustParseAddrPort("198.51.100.20:40004"),
		netip.MustParseAddrPort("198.51.100.20:40002"),
		netip.MustParseAddrPort("198.51.100.20:39998"),
		netip.MustParseAddrPort("198.51.100.20:40005"),
	}, probes)
}

func TestSymmetricNATProbesExtrapolateStride(t *testing.T) {
	announced := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:41000"),
		netip.MustParseAddrPort("198.51.100.20:42000"),
	}

	probes := symmetricNATProbes(announced, defaultSymmetricNATProbes, false)
	assert.Contains(t, probes, netip.MustParseAddrPort("198.51.100.20:43000"))
	assert.Contains(t, probes, netip.MustParseAddrPort("198.51.100.20:44000"))
}

func TestSymmetricNATProbesFillTheBudgetWithoutRepeating(t *testing.T) {
	announced := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:51234"),
	}

	probes := symmetricNATProbes(announced, defaultSymmetricNATProbes, false)
	require.Len(t, probes, defaultSymmetricNATProbes)
	seen := make(map[netip.AddrPort]struct{}, len(probes))
	for _, probe := range probes {
		assert.Equal(t, announced[0].Addr(), probe.Addr())
		assert.GreaterOrEqual(t, int(probe.Port()), symmetricNATMinProbePort)
		assert.NotContains(t, announced, probe)
		_, dup := seen[probe]
		assert.False(t, dup, "duplicate probe %v", probe)
		seen[probe] = struct{}{}
	}
}

func TestSymmetricNATProbesSpreadOverHosts(t *testing.T) {
	announced := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:40001"),
		netip.MustParseAddrPort("203.0.113.5:50000"),
		netip.MustParseAddrPort("203.0.113.5:50001"),
	}

	probes := symmetricNATProbes(announced, 64, false)
	byHost := make(map[netip.Addr]int)
	for _, probe := range probes {
		byHost[probe.Addr()]++
	}
	assert.Len(t, byHost, 2)
	for host, count := range byHost {
		assert.Greater(t, count, 16, "host %v got too few probes", host)
	}
}

func TestSymmetricNATProbesSkipPredictablePeers(t *testing.T) {
	// One announced port per host says nothing about the allocation, so the
	// announced address is punched and nothing is guessed...
	announced := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:40000")}
	assert.Empty(t, symmetricNATProbes(announced, 64, false))

	// ...unless the caller states that the peer is endpoint-dependent.
	assert.Len(t, symmetricNATProbes(announced, 64, true), 64)
}

func TestSymmetricNATProbesSkipIPv6(t *testing.T) {
	announced := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::20]:40000"),
		netip.MustParseAddrPort("[2001:db8::20]:51234"),
	}
	assert.Empty(t, symmetricNATProbes(announced, 64, true))
}

func TestSymmetricNATProbesStayInPortRange(t *testing.T) {
	announced := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:65534"),
		netip.MustParseAddrPort("198.51.100.20:65535"),
	}

	probes := symmetricNATProbes(announced, 128, false)
	require.NotEmpty(t, probes)
	for _, probe := range probes {
		assert.GreaterOrEqual(t, int(probe.Port()), symmetricNATMinProbePort)
	}
}

func TestSymmetricNATProbesRespectZeroLimit(t *testing.T) {
	announced := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:40001"),
	}
	assert.Empty(t, symmetricNATProbes(announced, 0, false))
}
