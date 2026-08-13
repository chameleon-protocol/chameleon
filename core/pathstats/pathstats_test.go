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
