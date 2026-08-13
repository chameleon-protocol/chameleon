package pathstats

import "testing"

func TestLossRate(t *testing.T) {
	// A path that has not sent anything is not a lossless path, but reporting
	// anything other than 0 here would make a fresh connection look either
	// perfect or broken depending on which way we rounded.
	if got := (Stats{}).LossRate(); got != 0 {
		t.Errorf("LossRate of an unused path = %v, want 0", got)
	}

	s := Stats{PacketsSent: 200, PacketsLost: 5}
	if got := s.LossRate(); got != 0.025 {
		t.Errorf("LossRate = %v, want 0.025", got)
	}
}
