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

package linkmon

import "testing"

func TestDiffStates(t *testing.T) {
	base := map[string]ifaceState{
		"lo0": {index: 1, up: true, addrs: []string{"127.0.0.1/8"}},
		"en0": {index: 2, up: true, addrs: []string{"192.168.1.5/24", "fe80::1/64"}},
	}
	clone := func(mutate func(map[string]ifaceState)) map[string]ifaceState {
		out := make(map[string]ifaceState, len(base))
		for k, v := range base {
			addrs := append([]string(nil), v.addrs...)
			out[k] = ifaceState{index: v.index, up: v.up, addrs: addrs}
		}
		mutate(out)
		return out
	}

	tests := []struct {
		name string
		cur  map[string]ifaceState
		want Change
	}{
		{"nothing moved", clone(func(map[string]ifaceState) {}), 0},
		{"interface appeared", clone(func(m map[string]ifaceState) {
			m["rmnet0"] = ifaceState{index: 3, up: true}
		}), ChangeLink},
		{"interface appeared with an address", clone(func(m map[string]ifaceState) {
			m["rmnet0"] = ifaceState{index: 3, up: true, addrs: []string{"10.4.0.9/30"}}
		}), ChangeLink | ChangeAddr},
		{"interface disappeared", clone(func(m map[string]ifaceState) {
			delete(m, "en0")
		}), ChangeLink},
		{"interface went down", clone(func(m map[string]ifaceState) {
			s := m["en0"]
			s.up = false
			m["en0"] = s
		}), ChangeLink},
		{"name reused by a new interface", clone(func(m map[string]ifaceState) {
			s := m["en0"]
			s.index = 9
			m["en0"] = s
		}), ChangeLink},
		{"address gained", clone(func(m map[string]ifaceState) {
			s := m["en0"]
			s.addrs = append(s.addrs, "192.168.1.6/24")
			m["en0"] = s
		}), ChangeAddr},
		{"address lost", clone(func(m map[string]ifaceState) {
			s := m["en0"]
			s.addrs = s.addrs[:1]
			m["en0"] = s
		}), ChangeAddr},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := diffStates(base, tc.cur); got != tc.want {
				t.Errorf("diffStates = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEnumerateInterfaces only checks that the real enumeration works and is
// stable: what it returns depends on the machine, and asserting anything
// about the interfaces of a build host would be asserting about the host.
func TestEnumerateInterfaces(t *testing.T) {
	first, err := enumerateInterfaces()
	if err != nil {
		t.Fatalf("enumerateInterfaces: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("no interfaces at all, not even a loopback")
	}
	second, err := enumerateInterfaces()
	if err != nil {
		t.Fatalf("enumerateInterfaces: %v", err)
	}
	if c := diffStates(first, second); c != 0 {
		t.Errorf("two snapshots taken back to back differ (%v); the diff is not stable", c)
	}
}
