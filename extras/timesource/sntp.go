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

package timesource

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"time"
)

const (
	ntpPacketSize = 48
	// Seconds between the NTP epoch (1900-01-01) and the Unix epoch.
	ntpEpochOffset = 2208988800

	// LI = 0, VN = 4, Mode = 3 (client).
	sntpClientHeader = 0x23

	defaultQueryTimeout = 3 * time.Second
	// A round trip longer than this says more about the path than about the
	// clock, and the offset it yields is worthless for a ±30s window.
	maxRoundTrip = 5 * time.Second
)

// DefaultServers are queried when no servers are configured. They are given as
// host:port on purpose: where UDP/123 is blocked, an operator can point this at
// an NTP responder listening on 53 or 443 without touching the code.
var DefaultServers = []string{
	"time.cloudflare.com:123",
	"time.google.com:123",
	"pool.ntp.org:123",
}

var (
	ErrNoServers      = errors.New("no time servers configured")
	errShortPacket    = errors.New("response too short")
	errNotServerMode  = errors.New("response is not a server reply")
	errUnsynchronized = errors.New("server reports an unsynchronized clock")
	errBadStratum     = errors.New("server reports an invalid stratum")
	errNonceMismatch  = errors.New("originate timestamp does not echo our nonce")
	errZeroTimestamp  = errors.New("server sent a zero transmit timestamp")
	errBadRoundTrip   = errors.New("implausible round trip time")
)

// Result is one measurement of the difference between the local clock and a
// network time source. It is unauthenticated; see the package documentation.
type Result struct {
	Server string
	// Time is the true time as of the moment the measurement finished.
	Time time.Time
	// Offset is Time minus the local clock reading at that same moment.
	Offset time.Duration
	RTT    time.Duration
}

// Source is an out-of-band, unauthenticated network time source.
type Source interface {
	Query(ctx context.Context) (Result, error)
}

// Exchanger performs one request/response round trip with a server. It exists
// so that the protocol logic can be tested without a network.
type Exchanger interface {
	Exchange(ctx context.Context, server string, req []byte) ([]byte, error)
}

// UDPExchanger is the real network transport: one datagram out, the first
// datagram back. A spoofed reply that beats the real one is not retried here;
// SNTPClient rejects it and moves on to the next server.
type UDPExchanger struct {
	Timeout time.Duration
}

func (e *UDPExchanger) Exchange(ctx context.Context, server string, req []byte) ([]byte, error) {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = defaultQueryTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

var _ Source = (*SNTPClient)(nil)

// SNTPClient is a minimal SNTP (RFC 4330) client: mode 3 requests, no state
// kept between queries. It implements only what a one-shot boot-time
// correction needs.
type SNTPClient struct {
	Servers  []string
	Exchange Exchanger
	// Timeout bounds a single server query; the caller's context still wins
	// if it expires first.
	Timeout time.Duration

	// rand and now are injection points for tests.
	rand io.Reader
	now  func() time.Time
}

// NewSNTPClient returns a client querying the given servers, or DefaultServers
// if servers is empty. Each entry is a host:port address.
func NewSNTPClient(servers []string) *SNTPClient {
	if len(servers) == 0 {
		servers = DefaultServers
	}
	return &SNTPClient{Servers: servers}
}

func (c *SNTPClient) localNow() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *SNTPClient) exchanger() Exchanger {
	if c.Exchange != nil {
		return c.Exchange
	}
	return &UDPExchanger{Timeout: c.Timeout}
}

// Query asks every configured server and returns the median measurement. All
// servers are tried even after one succeeds, because the median of several
// answers rejects a single grossly wrong one for free — but a single answer is
// enough. Requiring agreement would turn "two of three servers unreachable"
// into a bricked device, which is the failure this package exists to prevent,
// and it would buy no real security: the source is unauthenticated either way.
func (c *SNTPClient) Query(ctx context.Context) (Result, error) {
	if len(c.Servers) == 0 {
		return Result{}, ErrNoServers
	}
	var (
		results []Result
		errs    []error
	)
	for _, server := range c.Servers {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		res, err := c.queryOne(ctx, server)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", server, err))
			continue
		}
		results = append(results, res)
	}
	if len(results) == 0 {
		return Result{}, errors.Join(errs...)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Offset < results[j].Offset })
	return results[len(results)/2], nil
}

func (c *SNTPClient) queryOne(ctx context.Context, server string) (Result, error) {
	req := make([]byte, ntpPacketSize)
	req[0] = sntpClientHeader

	// RFC 4330 §5: the transmit timestamp is echoed back untouched, so a
	// random value in it doubles as a nonce that an off-path spoofer cannot
	// guess. The real send time is kept separately — the offset formula needs
	// T1, not the nonce.
	rnd := c.rand
	if rnd == nil {
		rnd = rand.Reader
	}
	var nonce [8]byte
	if _, err := io.ReadFull(rnd, nonce[:]); err != nil {
		return Result{}, err
	}
	copy(req[40:48], nonce[:])

	t1 := c.localNow()
	resp, err := c.exchanger().Exchange(ctx, server, req)
	t4 := c.localNow()
	if err != nil {
		return Result{}, err
	}
	if len(resp) < ntpPacketSize {
		return Result{}, errShortPacket
	}
	if li := resp[0] >> 6; li == 3 {
		return Result{}, errUnsynchronized
	}
	if mode := resp[0] & 0x07; mode != 4 {
		return Result{}, errNotServerMode
	}
	// Stratum 0 is a kiss-of-death packet carrying no time at all; above 15 is
	// unsynchronized or reserved.
	if stratum := resp[1]; stratum == 0 || stratum > 15 {
		return Result{}, errBadStratum
	}
	if !bytes.Equal(resp[24:32], nonce[:]) {
		return Result{}, errNonceMismatch
	}
	if binary.BigEndian.Uint64(resp[40:48]) == 0 {
		return Result{}, errZeroTimestamp
	}

	t2 := ntpTime(resp[32:40]) // server receive
	t3 := ntpTime(resp[40:48]) // server transmit
	rtt := t4.Sub(t1) - t3.Sub(t2)
	if rtt < 0 || rtt > maxRoundTrip {
		return Result{}, errBadRoundTrip
	}
	// Standard NTP offset, with the one-way delay assumed symmetric.
	offset := t3.Sub(t4) + rtt/2
	return Result{
		Server: server,
		Time:   t4.Add(offset),
		Offset: offset,
		RTT:    rtt,
	}, nil
}

// ntpTime converts a 64-bit NTP timestamp to a Go time. A cleared MSB means
// era 1 (RFC 4330 §3), which is what every timestamp becomes after 2036-02-07.
func ntpTime(b []byte) time.Time {
	sec := int64(binary.BigEndian.Uint32(b[0:4]))
	frac := int64(binary.BigEndian.Uint32(b[4:8]))
	if sec&0x80000000 == 0 {
		sec += 1 << 32
	}
	nsec := (frac * int64(time.Second)) >> 32
	return time.Unix(sec-ntpEpochOffset, nsec).UTC()
}
