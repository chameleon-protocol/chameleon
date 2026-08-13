// Package netem provides a pure user-space network impairment layer for tests.
//
// It wraps a net.PacketConn and applies loss, delay, jitter and rate limiting to
// the datagrams crossing it. Unlike tc/netem or dnctl it needs no root and no
// kernel support, so the same impairment profiles run on every platform we
// happen to test on. The price is fidelity: see tests/README.md, and the
// netem/kernel subpackage for the real thing.
package netem

import (
	"fmt"
	"strings"
	"time"
)

// Link describes the impairment applied to one direction of a Conn.
//
// The zero Link is a perfect link: it forwards everything, unchanged, inline on
// the caller's goroutine.
type Link struct {
	// Loss is the probability that a datagram is dropped, in [0, 1]. The draw is
	// independent per datagram; real networks lose in bursts, so a Loss link is
	// friendlier than the loss rate alone suggests.
	Loss float64

	// Delay is the one-way delay added to every datagram. A round trip crosses
	// two Links, so an RTT of 200ms means Delay of 100ms on each direction.
	Delay time.Duration

	// Jitter randomizes Delay by ±Jitter, drawn uniformly per datagram. Because
	// the draw is per datagram, a non-zero Jitter also reorders.
	Jitter time.Duration

	// Rate is the bandwidth limit in bytes per second, enforced by a token
	// bucket. Zero means unlimited.
	Rate int64

	// Burst is the token bucket depth in bytes. Zero picks a default of 20ms
	// worth of Rate, floored at 8KB. Ignored when Rate is zero.
	Burst int64

	// Queue is the maximum number of datagrams held waiting for tokens, beyond
	// which the link tail-drops. Zero picks defaultQueue when Rate is set, and
	// means unlimited otherwise -- a delay-only link is a propagation delay, not
	// a buffer, and capping it would drop the bandwidth-delay product on fast
	// links.
	Queue int

	// Blackhole drops every datagram, regardless of Loss. This is how a censor
	// that has decided to kill all UDP to a destination looks from the endpoint:
	// writes keep succeeding, nothing ever comes back.
	Blackhole bool

	// Shared, when set, replaces Rate, Burst and Queue with a shaper that every
	// Link pointing at the same Bottleneck contends for. It is the only way to
	// put two flows behind one buffer; see bottleneck.go.
	Shared *Bottleneck
}

const (
	defaultQueue      = 512
	defaultBurstFloor = 8192
	burstWindow       = 20 * time.Millisecond
)

func (l Link) burst() int64 {
	if l.Burst > 0 {
		return l.Burst
	}
	b := int64(float64(l.Rate) * burstWindow.Seconds())
	if b < defaultBurstFloor {
		b = defaultBurstFloor
	}
	return b
}

func (l Link) queueLimit() int {
	if l.Queue > 0 {
		return l.Queue
	}
	if l.Rate > 0 {
		return defaultQueue
	}
	return 0
}

// clean reports whether the link can forward inline, without a scheduler.
func (l Link) clean() bool {
	return !l.Blackhole && l.Loss == 0 && l.Delay == 0 && l.Jitter == 0 && l.Rate == 0 && l.Shared == nil
}

func (l Link) String() string {
	var parts []string
	if l.Blackhole {
		return "blackhole"
	}
	if l.Loss > 0 {
		parts = append(parts, fmt.Sprintf("loss=%.3g%%", l.Loss*100))
	}
	if l.Delay > 0 {
		parts = append(parts, "delay="+l.Delay.String())
	}
	if l.Jitter > 0 {
		parts = append(parts, "jitter="+l.Jitter.String())
	}
	if l.Rate > 0 {
		parts = append(parts, fmt.Sprintf("rate=%dB/s", l.Rate))
	}
	if l.Shared != nil {
		parts = append(parts, fmt.Sprintf("shared=%.0fB/s", l.Shared.rate))
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, " ")
}

// Profile is the impairment of a full path: what the endpoint sends (Up) and
// what it receives (Down).
//
// Only one endpoint needs to be wrapped. Wrapping the client alone with an RTT
// of 200ms gives both peers a 200ms round trip, because every packet of the
// exchange crosses the client's socket exactly once in each direction.
type Profile struct {
	Name string
	Up   Link
	Down Link
}

func (p Profile) String() string {
	name := p.Name
	if name == "" {
		name = "unnamed"
	}
	return fmt.Sprintf("%s{up: %s, down: %s}", name, p.Up, p.Down)
}

// Named returns a copy of p labelled for test output.
func (p Profile) Named(name string) Profile {
	p.Name = name
	return p
}

// WithLoss returns a copy of p that drops datagrams with probability rate in
// each direction independently.
func (p Profile) WithLoss(rate float64) Profile {
	p.Up.Loss, p.Down.Loss = rate, rate
	return p
}

// WithRTT returns a copy of p with rtt split evenly across the two directions.
func (p Profile) WithRTT(rtt time.Duration) Profile {
	p.Up.Delay, p.Down.Delay = rtt/2, rtt/2
	return p
}

// WithJitter returns a copy of p that varies each direction's delay by ±jitter/2.
func (p Profile) WithJitter(jitter time.Duration) Profile {
	p.Up.Jitter, p.Down.Jitter = jitter/2, jitter/2
	return p
}

// WithRate returns a copy of p limited to bytesPerSec in each direction.
func (p Profile) WithRate(bytesPerSec int64) Profile {
	p.Up.Rate, p.Down.Rate = bytesPerSec, bytesPerSec
	return p
}

// WithBlackhole returns a copy of p that drops everything in both directions.
func (p Profile) WithBlackhole(on bool) Profile {
	p.Up.Blackhole, p.Down.Blackhole = on, on
	return p
}

// Clean is a pass-through profile. It is the baseline every other measurement
// must be compared against: a Conn is not a *net.UDPConn, so it costs
// throughput even when it impairs nothing.
func Clean() Profile { return Profile{Name: "clean"} }

// Loss returns a profile that drops the given fraction of datagrams in each
// direction.
func Loss(rate float64) Profile {
	return Clean().WithLoss(rate).Named(fmt.Sprintf("loss%.3g%%", rate*100))
}

// RTT returns a profile with the given round-trip delay.
func RTT(rtt time.Duration) Profile {
	return Clean().WithRTT(rtt).Named("rtt" + rtt.String())
}

// Blocked returns a profile that drops all UDP, in both directions. This is the
// hard-censorship case: QUIC cannot recover, only a different transport can.
func Blocked() Profile {
	return Clean().WithBlackhole(true).Named("udp-blocked")
}

// RateLimited returns a profile with a token bucket in each direction. This is
// the soft-censorship case: UDP is allowed but throttled hard enough that the
// user is expected to give up and fall back to TCP.
func RateLimited(bytesPerSec int64) Profile {
	return Clean().WithRate(bytesPerSec).Named(fmt.Sprintf("rate%dKB/s", bytesPerSec/1024))
}

// Standard is the impairment matrix the transport is expected to survive. It is
// the default grid for regression runs, so that "throughput regressed by less
// than X%" refers to a fixed, named set of conditions rather than whatever the
// author happened to try.
func Standard() []Profile {
	return []Profile{
		Clean(),
		Loss(0.01),
		Loss(0.05),
		RTT(50 * time.Millisecond),
		RTT(200 * time.Millisecond),
		RTT(200 * time.Millisecond).WithLoss(0.01).Named("rtt200ms+loss1%"),
		RTT(50 * time.Millisecond).WithLoss(0.05).Named("rtt50ms+loss5%"),
		RateLimited(1 << 20).WithRTT(50 * time.Millisecond).Named("rate1MB/s+rtt50ms"),
	}
}
