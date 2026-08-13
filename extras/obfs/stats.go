package obfs

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// Stats counts the packets the obfuscation layer threw away.
//
// Every one of these is a silent drop: ReadFrom loops and reads again, so
// nobody up the stack ever learns that a packet arrived and was refused. That
// is required of the wire protocol - a prober must not be able to tell a
// rejection from an idle socket - but it also means a misconfigured deployment
// looks exactly like an idle one. These counters are the only thing that tells
// a wrong password from a broken clock from a firewall that ate the traffic,
// short of a packet capture on both ends.
//
// Safe for concurrent use. Recording a rejection costs one atomic add on a
// path that has already paid for a syscall and an AEAD open.
type Stats struct {
	// Dropped is every packet the obfuscator refused, whatever the reason.
	// Obfuscators that classify their rejections also bump exactly one of the
	// counters below, so for those the classes sum to Dropped.
	Dropped atomic.Uint64

	// Malformed is a packet that could not be ours by its shape alone - too
	// short to hold the overhead, or authentic but with a nonsensical length.
	// On an open port this is mostly internet background noise.
	Malformed atomic.Uint64

	// AEADFailed is a packet that failed authentication: the wrong password on
	// one end, a middlebox rewriting payloads, or an unrelated sender.
	AEADFailed atomic.Uint64

	// ClockSkew is a packet that authenticated correctly but carried a
	// timestamp outside the accepted window. It is deliberately separate from
	// AEADFailed: the two have completely different fixes, and merging them
	// leaves the operator with "packets are being dropped" and nothing else.
	ClockSkew atomic.Uint64

	// Replayed is a packet whose salt has been seen before, i.e. someone is
	// replaying recorded traffic at us. Unlike the others this one is not a
	// misconfiguration, it is an active prober.
	Replayed atomic.Uint64

	// LastSkewSeconds is the signed difference between the peer's clock and
	// ours, in seconds, as of the most recent ClockSkew rejection. Positive
	// means the peer is ahead. It is what turns the counter into an actionable
	// message.
	LastSkewSeconds atomic.Int64
}

// StatsSnapshot is a consistent-enough reading of a Stats for reporting. The
// counters are read one at a time, so a snapshot taken under load may be off
// by the packets that arrived while it was being taken.
type StatsSnapshot struct {
	Dropped    uint64
	Malformed  uint64
	AEADFailed uint64
	ClockSkew  uint64
	Replayed   uint64
	LastSkew   time.Duration
}

func (s *Stats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		Dropped:    s.Dropped.Load(),
		Malformed:  s.Malformed.Load(),
		AEADFailed: s.AEADFailed.Load(),
		ClockSkew:  s.ClockSkew.Load(),
		Replayed:   s.Replayed.Load(),
		LastSkew:   time.Duration(s.LastSkewSeconds.Load()) * time.Second,
	}
}

// recordSkew notes a timestamp-window rejection along with how far off the
// peer's clock appeared to be.
func (s *Stats) recordSkew(peerUnix, localUnix int64) {
	s.ClockSkew.Add(1)
	s.LastSkewSeconds.Store(peerUnix - localUnix)
}

// ClockSkewHint describes a clock problem in words, or returns "" if the
// counters do not show one.
//
// A node whose clock is wrong drops every packet its peer sends and reports
// nothing, which from the outside is indistinguishable from a wrong password.
// The mesh runs on routers, Raspberry Pis and other hardware that boots
// without a battery-backed clock and may never reach an NTP server, so this is
// a routine failure rather than an exotic one - and it stays unsolved for
// hours unless something says the word "clock" out loud.
func (s StatsSnapshot) ClockSkewHint() string {
	if s.ClockSkew == 0 {
		return ""
	}
	skew, direction := s.LastSkew, "ahead of"
	if skew < 0 {
		skew, direction = -skew, "behind"
	}
	return fmt.Sprintf("obfs: %d packet(s) rejected by the timestamp window; the peer's clock reads about %s %s ours - check NTP on both ends",
		s.ClockSkew, skew, direction)
}

// statsHolder is implemented by obfuscators that classify their own
// rejections. wrapPacketConn adopts such an obfuscator's Stats instead of
// creating its own, so the per-class counts and the total end up in one place.
type statsHolder interface {
	Stats() *Stats
}

// StatsOf returns the obfuscation counters of a PacketConn produced by one of
// the WrapPacketConn* functions, or nil for any other PacketConn.
func StatsOf(conn net.PacketConn) *Stats {
	if h, ok := conn.(statsHolder); ok {
		return h.Stats()
	}
	return nil
}
