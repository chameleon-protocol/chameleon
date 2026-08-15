package brutal

import (
	"testing"
	"time"

	"github.com/chameleon-protocol/quic-go/congestion"
	"github.com/chameleon-protocol/quic-go/monotime"
)

// feedAckRate drives a single sampling slot with the given number of acked and
// lost packets and returns the resulting ackRate.
//
// The RTT source has to be installed because the ack rate now depends on it:
// loss is only compensated for when the path is not queueing. An unqueued path
// -- smoothed round trip equal to the minimum -- is what this test wants, so
// that what it measures is the loss ratio and nothing else. Production always
// installs the provider inside the lock that installs the controller, before
// the connection can call anything, so a nil provider is not a reachable state.
func feedAckRate(disableLossCompensation bool, ackCount, lossCount int) float64 {
	b := NewBrutalSender(1000000, disableLossCompensation)
	b.SetRTTStatsProvider(newFakeRTT(20*time.Millisecond, 20*time.Millisecond).provider())
	acked := make([]congestion.AckedPacketInfo, ackCount)
	lost := make([]congestion.LostPacketInfo, lossCount)
	// eventTime lands in a fixed slot; a single event carries enough samples.
	b.OnCongestionEventEx(0, monotime.Time(5*time.Second), acked, lost)
	return b.ackRate
}

func TestBrutalLossCompensation(t *testing.T) {
	tests := []struct {
		name      string
		ack, loss int
		want      float64 // expected ackRate when compensation is ENABLED
	}{
		{"no loss", 100, 0, 1.0},
		{"20% loss", 80, 20, 0.8},
		{"50% loss clamps to floor", 50, 50, minAckRate}, // 0.5 clamped up to 0.8
		{"few samples stays 1", 10, 5, 1.0},              // below minSampleCount
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compensation enabled (default behavior): ackRate reacts to loss.
			if got := feedAckRate(false, tt.ack, tt.loss); got != tt.want {
				t.Errorf("compensation on: ackRate = %v, want %v", got, tt.want)
			}
			// Compensation disabled: ackRate must stay pinned at 1 regardless.
			if got := feedAckRate(true, tt.ack, tt.loss); got != 1.0 {
				t.Errorf("compensation off: ackRate = %v, want 1.0", got)
			}
		})
	}
}
