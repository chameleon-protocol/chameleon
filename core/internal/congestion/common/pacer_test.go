package common

import (
	"testing"
	"time"

	"github.com/chameleon-protocol/quic-go/congestion"
	"github.com/chameleon-protocol/quic-go/monotime"
)

// The burst cap is the one thing about this pacer that is a fingerprint
// decision rather than a performance one, and it is the half of it that has no
// other observable consequence: steady-state throughput does not depend on it,
// because budget only accumulates while the sender is idle. So nothing else in
// the tree fails when it changes, and it needs its own assertion or it does not
// have one.
//
// These are assertions about the Pacer's own contract. Both BBR and Brutal
// embed it, and neither is named here on purpose: the number being pinned is
// upstream quic-go's, and what it protects is that this tree's first burst
// after an idle period looks like upstream's rather than twice upstream's --
// which is what it did before, at four milliseconds of bandwidth.

// fixedBandwidth is the getBandwidth callback both controllers supply, reduced
// to the only thing the burst cap reads out of it.
func fixedBandwidth(bps congestion.ByteCount) func() congestion.ByteCount {
	return func() congestion.ByteCount { return bps }
}

// TestIdleBurstIsTwoPacingDelays pins the bandwidth half of the cap. Upstream
// quic-go lets an idle pacer accumulate MinPacingDelay + TimerGranularity of
// bandwidth, which is 1ms + 1ms; TimerGranularity is not exported through the
// congestion package, so the multiplier is written as two and checked here.
func TestIdleBurstIsTwoPacingDelays(t *testing.T) {
	// A rate high enough that the bandwidth term is the binding one: below
	// about 6.4 MB/s the ten-packet floor wins and the multiplier is invisible.
	const bps = 100 << 20
	p := NewPacer(fixedBandwidth(bps))
	p.SetMaxDatagramSize(congestion.InitialPacketSize)

	want := congestion.ByteCount((2 * congestion.MinPacingDelay).Seconds() * bps)
	// A pacer that has never sent reports the cap directly, which is also the
	// state a connection is in when it starts.
	if got := p.Budget(monotime.Time(time.Hour)); got != want {
		t.Errorf("idle burst %d B at %d B/s, want %d B (%v of bandwidth)",
			got, bps, want, 2*congestion.MinPacingDelay)
	}

	// And after a real idle period, which is the case that puts the burst on
	// the wire: the budget accumulated over a whole second is still capped.
	base := monotime.Time(time.Hour)
	p.SentPacket(base, congestion.InitialPacketSize)
	if got := p.Budget(base.Add(time.Second)); got != want {
		t.Errorf("burst after a second idle is %d B, want the %d B cap", got, want)
	}
}

// TestIdleBurstFloorIsTenPackets pins the other half. Ten packets is upstream's
// figure too, and it is what binds at every rate a user is likely to declare.
func TestIdleBurstFloorIsTenPackets(t *testing.T) {
	const bps = 1 << 20 // 2ms of this is under two packets
	p := NewPacer(fixedBandwidth(bps))
	p.SetMaxDatagramSize(congestion.InitialPacketSize)

	want := congestion.ByteCount(maxBurstPackets) * congestion.InitialPacketSize
	if got := p.Budget(monotime.Time(time.Hour)); got != want {
		t.Errorf("idle burst %d B at %d B/s, want the %d packet floor of %d B",
			got, bps, maxBurstPackets, want)
	}
}
