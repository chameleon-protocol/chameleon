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

package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/apernet/quic-go/quicvarint"
)

// These two seeds are used because all four of their derived ranges happen to
// be disjoint, which lets the tests below check for non-overlapping length
// distributions directly instead of settling for "the ranges differ".
var (
	seedA = []byte("seed-40")
	seedB = []byte("seed-112")
)

const sampleCount = 500

func sampleLengths(t *testing.T, p padding) map[int]bool {
	t.Helper()
	lengths := make(map[int]bool, sampleCount)
	for i := 0; i < sampleCount; i++ {
		s := p.generate()
		if strings.ContainsFunc(s, func(r rune) bool { return !strings.ContainsRune(paddingChars, r) }) {
			t.Fatalf("padding contains a character outside the allowed set: %q", s)
		}
		lengths[len(s)] = true
	}
	return lengths
}

func rangesOf(ps *PaddingScheme) []padding {
	return []padding{ps.AuthRequest, ps.AuthResponse, ps.TCPRequest, ps.TCPResponse}
}

func TestPaddingSchemeNoSeed(t *testing.T) {
	// Deployments that don't configure a seed must keep the exact behavior
	// they had before the scheme became configurable.
	want := []padding{
		{Min: 256, Max: 2048},
		{Min: 256, Max: 2048},
		{Min: 64, Max: 512},
		{Min: 128, Max: 1024},
	}
	for _, seed := range [][]byte{nil, {}} {
		got := rangesOf(NewPaddingScheme(seed))
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("seed %v: range %d = %+v, want %+v", seed, i, got[i], want[i])
			}
			lengths := sampleLengths(t, got[i])
			for n := range lengths {
				if n < want[i].Min || n >= want[i].Max {
					t.Fatalf("range %d: length %d outside %+v", i, n, want[i])
				}
			}
			if len(lengths) < sampleCount/2 {
				t.Fatalf("range %d: only %d distinct lengths in %d samples, padding is not random enough",
					i, len(lengths), sampleCount)
			}
		}
	}
}

func TestPaddingSchemeSameSeedReproducible(t *testing.T) {
	first, second := rangesOf(NewPaddingScheme(seedA)), rangesOf(NewPaddingScheme(seedA))
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("range %d: %+v != %+v, the same seed must give the same distribution",
				i, first[i], second[i])
		}
	}
	// A seeded scheme must still pick a fresh length every time, otherwise the
	// padding would become a constant and an even better fingerprint.
	for i, p := range first {
		if lengths := sampleLengths(t, p); len(lengths) < 2 {
			t.Fatalf("range %d: %d distinct length(s) in %d samples", i, len(lengths), sampleCount)
		}
	}
}

func TestPaddingSchemeSeedChangesDistribution(t *testing.T) {
	a, b := rangesOf(NewPaddingScheme(seedA)), rangesOf(NewPaddingScheme(seedB))
	for i := range a {
		lenA, lenB := sampleLengths(t, a[i]), sampleLengths(t, b[i])
		for n := range lenA {
			if n < a[i].Min || n >= a[i].Max {
				t.Fatalf("range %d: length %d outside %+v", i, n, a[i])
			}
			if lenB[n] {
				t.Fatalf("range %d: length %d produced under both seeds (%+v vs %+v)", i, n, a[i], b[i])
			}
		}
		for n := range lenB {
			if n < b[i].Min || n >= b[i].Max {
				t.Fatalf("range %d: length %d outside %+v", i, n, b[i])
			}
		}
	}
}

// The point of seeding is that two deployments don't share a distribution, so
// distinct seeds must not collapse onto the same ranges.
func TestPaddingSchemeSeedsAreDistinct(t *testing.T) {
	seen := make(map[string]string)
	for i := 0; i < 64; i++ {
		seed := fmt.Sprintf("deployment-%d", i)
		for j, p := range rangesOf(NewPaddingScheme([]byte(seed))) {
			key := fmt.Sprintf("%d:%d-%d", j, p.Min, p.Max)
			if other, ok := seen[key]; ok {
				t.Fatalf("seeds %q and %q share range %d %+v", other, seed, j, p)
			}
			seen[key] = seed
		}
	}
}

// Derived padding must stay within what the read side accepts, otherwise a
// seeded peer would break connections instead of merely looking different.
func TestPaddingSchemeWithinProtocolLimits(t *testing.T) {
	for i := 0; i < 256; i++ {
		ps := NewPaddingScheme([]byte(fmt.Sprintf("deployment-%d", i)))
		for j, p := range rangesOf(ps) {
			if p.Min < 0 || p.Max > MaxPaddingLength {
				t.Fatalf("seed %d: range %d = %+v exceeds MaxPaddingLength %d", i, j, p, MaxPaddingLength)
			}
		}
	}
}

func TestWriteTCPRequestPaddingFollowsScheme(t *testing.T) {
	const addr = "google.com:443"
	seeded := NewPaddingScheme(seedA)
	tests := []struct {
		name string
		ps   *PaddingScheme
		want padding
	}{
		// A nil scheme is what a caller with nothing configured passes down.
		{name: "nil scheme", ps: nil, want: defaultPaddingScheme.TCPRequest},
		{name: "seeded", ps: seeded, want: seeded.TCPRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				var buf bytes.Buffer
				if err := WriteTCPRequest(&buf, addr, tt.ps); err != nil {
					t.Fatal(err)
				}
				frame := bytes.Clone(buf.Bytes())
				// The frame must remain readable by a peer using any scheme.
				buf.Next(int(quicvarint.Len(FrameTypeTCPRequest)))
				got, err := ReadTCPRequest(&buf)
				if err != nil {
					t.Fatal(err)
				}
				if got != addr {
					t.Fatalf("ReadTCPRequest() = %q, want %q", got, addr)
				}
				if buf.Len() != 0 {
					t.Fatalf("%d bytes left after ReadTCPRequest()", buf.Len())
				}
				r := bytes.NewReader(frame)
				readVarint(t, r) // frame type
				addrLen := readVarint(t, r)
				discard(t, r, int(addrLen))
				padLen := int(readVarint(t, r))
				if padLen != r.Len() {
					t.Fatalf("padding length field says %d, %d bytes follow", padLen, r.Len())
				}
				if padLen < tt.want.Min || padLen >= tt.want.Max {
					t.Fatalf("padding length %d outside %+v", padLen, tt.want)
				}
			}
		})
	}
}

func TestWriteTCPResponsePaddingFollowsScheme(t *testing.T) {
	const msg = "Connected"
	ps := NewPaddingScheme(seedA)
	for i := 0; i < 100; i++ {
		var buf bytes.Buffer
		if err := WriteTCPResponse(&buf, true, msg, ps); err != nil {
			t.Fatal(err)
		}
		frame := bytes.Clone(buf.Bytes())
		gotOK, gotMsg, err := ReadTCPResponse(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if !gotOK || gotMsg != msg {
			t.Fatalf("ReadTCPResponse() = %v, %q, want true, %q", gotOK, gotMsg, msg)
		}
		if buf.Len() != 0 {
			t.Fatalf("%d bytes left after ReadTCPResponse()", buf.Len())
		}
		r := bytes.NewReader(frame)
		discard(t, r, 1) // status
		msgLen := readVarint(t, r)
		discard(t, r, int(msgLen))
		padLen := int(readVarint(t, r))
		if padLen != r.Len() {
			t.Fatalf("padding length field says %d, %d bytes follow", padLen, r.Len())
		}
		if padLen < ps.TCPResponse.Min || padLen >= ps.TCPResponse.Max {
			t.Fatalf("padding length %d outside %+v", padLen, ps.TCPResponse)
		}
	}
}

func TestAuthRequestToHeaderPaddingFollowsScheme(t *testing.T) {
	seeded := NewPaddingScheme(seedA)
	tests := []struct {
		name string
		ps   *PaddingScheme
		want padding
	}{
		{name: "nil scheme", ps: nil, want: defaultPaddingScheme.AuthRequest},
		{name: "seeded", ps: seeded, want: seeded.AuthRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				h := make(http.Header)
				AuthRequestToHeader(h, AuthRequest{Auth: "pass", Rx: 100}, tt.ps)
				padLen := len(h.Get(CommonHeaderPadding))
				if padLen < tt.want.Min || padLen >= tt.want.Max {
					t.Fatalf("padding length %d outside %+v", padLen, tt.want)
				}
				if got := AuthRequestFromHeader(h); got.Auth != "pass" || got.Rx != 100 {
					t.Fatalf("AuthRequestFromHeader() = %+v, want {pass 100}", got)
				}
			}
		})
	}
}

func TestAuthResponseToHeaderPaddingFollowsScheme(t *testing.T) {
	seeded := NewPaddingScheme(seedA)
	tests := []struct {
		name string
		ps   *PaddingScheme
		want padding
	}{
		{name: "nil scheme", ps: nil, want: defaultPaddingScheme.AuthResponse},
		{name: "seeded", ps: seeded, want: seeded.AuthResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				h := make(http.Header)
				AuthResponseToHeader(h, AuthResponse{UDPEnabled: true, Rx: 100}, tt.ps)
				padLen := len(h.Get(CommonHeaderPadding))
				if padLen < tt.want.Min || padLen >= tt.want.Max {
					t.Fatalf("padding length %d outside %+v", padLen, tt.want)
				}
				if got := AuthResponseFromHeader(h); !got.UDPEnabled || got.Rx != 100 {
					t.Fatalf("AuthResponseFromHeader() = %+v, want {true 100 false}", got)
				}
			}
		})
	}
}

func readVarint(t *testing.T, r *bytes.Reader) uint64 {
	t.Helper()
	v, err := quicvarint.Read(r)
	if err != nil {
		t.Fatalf("quicvarint.Read() error = %v", err)
	}
	return v
}

func discard(t *testing.T, r *bytes.Reader, n int) {
	t.Helper()
	if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
		t.Fatalf("short frame: %v", err)
	}
}
