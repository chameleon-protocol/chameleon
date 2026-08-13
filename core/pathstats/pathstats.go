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

// Package pathstats reports transport-level health for a single network path.
//
// The mesh has to pick one path out of several and both ends have to be able
// to say why a path was abandoned, which needs numbers rather than an up/down
// bit. Today every path is a QUIC connection, but nothing here mentions QUIC:
// a path over a different carrier has to be comparable to a QUIC one on the
// same terms.
package pathstats

import (
	"time"

	"github.com/apernet/quic-go"
)

// Stats is a point-in-time reading of one path.
type Stats struct {
	// MinRTT is the lowest round-trip time observed, which is as close as we
	// get to the path's propagation delay. SmoothedRTT includes queueing and is
	// what the congestion controller reacts to, so the gap between the two is
	// the bufferbloat on the path.
	MinRTT      time.Duration
	LatestRTT   time.Duration
	SmoothedRTT time.Duration
	// RTTVariance is the mean deviation of the RTT samples. A path with a low
	// RTT and a high variance is worse for interactive traffic than its
	// SmoothedRTT suggests.
	RTTVariance time.Duration

	BytesSent       uint64
	PacketsSent     uint64
	BytesReceived   uint64
	PacketsReceived uint64
	// BytesLost and PacketsLost do not increase monotonically: a packet that
	// was declared lost and then arrives is subtracted again.
	BytesLost   uint64
	PacketsLost uint64
}

// FromQUIC reads the current statistics of a QUIC connection.
//
// Note that quic-go's ConnectionState carries TLS state and feature
// negotiation only - RTT and loss counters live on ConnectionStats, which is a
// separate call.
func FromQUIC(conn *quic.Conn) Stats {
	s := conn.ConnectionStats()
	return Stats{
		MinRTT:      s.MinRTT,
		LatestRTT:   s.LatestRTT,
		SmoothedRTT: s.SmoothedRTT,
		RTTVariance: s.MeanDeviation,

		BytesSent:       s.BytesSent,
		PacketsSent:     s.PacketsSent,
		BytesReceived:   s.BytesReceived,
		PacketsReceived: s.PacketsReceived,
		BytesLost:       s.BytesLost,
		PacketsLost:     s.PacketsLost,
	}
}

// LossRate is the fraction of sent packets currently considered lost, 0 if
// nothing has been sent yet.
func (s Stats) LossRate() float64 {
	if s.PacketsSent == 0 {
		return 0
	}
	return float64(s.PacketsLost) / float64(s.PacketsSent)
}
