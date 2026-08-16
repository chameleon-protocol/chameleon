package realm

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// discoSecret is a fixed 32-byte stand-in for the TLS exporter's output. The
// real one is per-connection and neither end chooses it; nothing in the envelope
// depends on where it came from, which is the point of taking it as bytes.
var discoSecret = []byte("disco-test-secret-32-bytes-long!")

func discoTestKeys(t testing.TB) (client, server *DiscoKeys) {
	t.Helper()
	client, err := NewDiscoKeys(discoSecret, false)
	if err != nil {
		t.Fatalf("client keys: %v", err)
	}
	server, err = NewDiscoKeys(discoSecret, true)
	if err != nil {
		t.Fatalf("server keys: %v", err)
	}
	return client, server
}

var (
	discoTestAddr4 = netip.MustParseAddrPort("198.51.100.7:4433")
	discoTestAddr6 = netip.MustParseAddrPort("[2001:db8::1]:443")
	discoTestNow   = time.Unix(1_700_000_000, 0)
)

func discoTestPackets() []DiscoPacket {
	return []DiscoPacket{
		{
			Header: DiscoHeader{Type: DiscoProbeType},
			Probe:  &DiscoProbe{Token: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, TxMicros: 1234567890123},
		},
		{
			Header: DiscoHeader{Type: DiscoPongType},
			Pong: &DiscoPong{
				Token:        [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
				TxMicrosEcho: 1234567890123,
				ObservedAddr: discoTestAddr4,
			},
		},
		{
			Header: DiscoHeader{Type: DiscoPongType},
			Pong: &DiscoPong{
				TxMicrosEcho: -1,
				ObservedAddr: discoTestAddr6,
			},
		},
		{
			Header: DiscoHeader{Type: DiscoCallMeType},
			CallMe: &DiscoCallMe{Candidates: []DiscoCandidate{
				{Addr: discoTestAddr4, Priority: 200},
				{Addr: discoTestAddr6, Priority: 1},
			}},
		},
		{
			Header: DiscoHeader{Type: DiscoCallMeType},
			CallMe: &DiscoCallMe{},
		},
		{
			Header: DiscoHeader{Type: DiscoBindType},
			Bind:   &DiscoBind{Nonce: [16]byte{0xaa}, ClaimedAddr: discoTestAddr6},
		},
		{
			Header:  DiscoHeader{Type: DiscoBindAckType},
			BindAck: &DiscoBindAck{Nonce: [16]byte{0xbb}, ObservedAddr: discoTestAddr4},
		},
	}
}

func TestDiscoRoundTripsEveryPacketType(t *testing.T) {
	client, server := discoTestKeys(t)
	for i, want := range discoTestPackets() {
		wire, err := EncodeDisco(want, client, uint32(i+1), discoTestNow, 400)
		if err != nil {
			t.Fatalf("%s: encode: %v", want.Header.Type, err)
		}
		got, err := DecodeDisco(wire, server, discoTestNow)
		if err != nil {
			t.Fatalf("%s: decode: %v", want.Header.Type, err)
		}
		if got.Header.Type != want.Header.Type {
			t.Errorf("type = %s, want %s", got.Header.Type, want.Header.Type)
		}
		if got.Header.Seq != uint32(i+1) {
			t.Errorf("%s: seq = %d, want %d", want.Header.Type, got.Header.Seq, i+1)
		}
		if !got.Header.TS.Equal(discoTestNow) {
			t.Errorf("%s: ts = %v, want %v", want.Header.Type, got.Header.TS, discoTestNow)
		}
		switch want.Header.Type {
		case DiscoProbeType:
			if got.Probe == nil || *got.Probe != *want.Probe {
				t.Errorf("PROBE payload = %+v, want %+v", got.Probe, want.Probe)
			}
		case DiscoPongType:
			if got.Pong == nil || *got.Pong != *want.Pong {
				t.Errorf("PONG payload = %+v, want %+v", got.Pong, want.Pong)
			}
		case DiscoCallMeType:
			if got.CallMe == nil || len(got.CallMe.Candidates) != len(want.CallMe.Candidates) {
				t.Fatalf("CALLME payload = %+v, want %+v", got.CallMe, want.CallMe)
			}
			for j, c := range want.CallMe.Candidates {
				if got.CallMe.Candidates[j] != c {
					t.Errorf("CALLME candidate %d = %+v, want %+v", j, got.CallMe.Candidates[j], c)
				}
			}
		case DiscoBindType:
			if got.Bind == nil || *got.Bind != *want.Bind {
				t.Errorf("BIND payload = %+v, want %+v", got.Bind, want.Bind)
			}
		case DiscoBindAckType:
			if got.BindAck == nil || *got.BindAck != *want.BindAck {
				t.Errorf("BINDACK payload = %+v, want %+v", got.BindAck, want.BindAck)
			}
		}
	}
}

// TestDiscoPacketIsExactlyTheRequestedLength pins the property the whole format
// exists to have. The padding target is chosen by the caller from lengths the
// connection already sends at, so a packet that came out one byte off would land
// in a length bucket of its own, which is the beacon a fixed 1250-byte target
// was measured to be at 100% detection.
func TestDiscoPacketIsExactlyTheRequestedLength(t *testing.T) {
	client, _ := discoTestKeys(t)
	// discoMinWire itself is below every real packet: it is the envelope plus a
	// header and no payload at all, and it exists as the demultiplexer's cheapest
	// rejection rather than as a length anything is sent at.
	for _, padTo := range []int{100, 1439, discoMaxWire} {
		for _, p := range discoTestPackets() {
			wire, err := EncodeDisco(p, client, 1, discoTestNow, padTo)
			if err != nil {
				t.Fatalf("padTo %d, %s: %v", padTo, p.Header.Type, err)
			}
			if len(wire) != padTo {
				t.Errorf("padTo %d, %s: wire length = %d", padTo, p.Header.Type, len(wire))
			}
		}
	}
}

func TestDiscoRefusesLengthsItCannotProduce(t *testing.T) {
	client, _ := discoTestKeys(t)
	probe := discoTestPackets()[0]
	for _, padTo := range []int{0, discoMinWire - 1, discoMaxWire + 1} {
		if _, err := EncodeDisco(probe, client, 1, discoTestNow, padTo); !errors.Is(err, ErrInvalidDiscoPacket) {
			t.Errorf("padTo %d: err = %v, want ErrInvalidDiscoPacket", padTo, err)
		}
	}
	// A payload that does not fit is an error rather than a truncation: a
	// truncated CALLME would authenticate and then decode to a different set of
	// candidates than the sender meant.
	big := DiscoPacket{Header: DiscoHeader{Type: DiscoCallMeType}, CallMe: &DiscoCallMe{}}
	for i := 0; i < DiscoMaxCandidates; i++ {
		big.CallMe.Candidates = append(big.CallMe.Candidates, DiscoCandidate{Addr: discoTestAddr6})
	}
	if _, err := EncodeDisco(big, client, 1, discoTestNow, discoMinWire); !errors.Is(err, ErrInvalidDiscoPacket) {
		t.Errorf("oversized payload: err = %v, want ErrInvalidDiscoPacket", err)
	}
}

// TestDiscoPacketsRepeatOnlyTheTag is the property that decides whether this
// format can ship at all.
//
// An exact repeat of a wide field across packets of one flow is not something a
// data flow produces, and it is what the cheapest deployable classifier looks
// for. This envelope has exactly one such field -- the eight-byte demux tag,
// which cannot avoid repeating because being looked up in a table is its whole
// purpose -- and it is only safe because the obfuscator underneath seals it.
// Every other byte offset must vary, so that stripping the obfuscator away
// cannot expose a second one.
func TestDiscoPacketsRepeatOnlyTheTag(t *testing.T) {
	client, _ := discoTestKeys(t)
	const n = 256
	const padTo = 1200
	packets := make([][]byte, n)
	for i := range packets {
		wire, err := EncodeDisco(discoTestPackets()[0], client, uint32(i+1), discoTestNow, padTo)
		if err != nil {
			t.Fatal(err)
		}
		packets[i] = wire
	}
	for off := 0; off < padTo; off++ {
		distinct := map[byte]struct{}{}
		for _, p := range packets {
			distinct[p[off]] = struct{}{}
		}
		constant := len(distinct) == 1
		wantConstant := off < discoTagLen
		if constant != wantConstant {
			t.Errorf("byte %d: constant over %d packets = %v, want %v (%d distinct values)",
				off, n, constant, wantConstant, len(distinct))
		}
	}
}

// TestDiscoDirectionsDoNotShareKeys: a packet reflected back at its sender must
// not authenticate. Each end seals with the key the other opens with, so a
// reflection does not even match a tag.
func TestDiscoDirectionsDoNotShareKeys(t *testing.T) {
	client, server := discoTestKeys(t)
	wire, err := EncodeDisco(discoTestPackets()[0], client, 1, discoTestNow, 200)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDisco(wire, client, discoTestNow); !errors.Is(err, ErrNotDisco) {
		t.Errorf("a client's own packet decoded back at it: %v", err)
	}
	if _, err := DecodeDisco(wire, server, discoTestNow); err != nil {
		t.Errorf("the server could not decode the client's packet: %v", err)
	}
}

// TestDiscoKeysAreSecretSpecific: two connections must share nothing. A
// reconnect derives a new exporter secret, so a packet from the old connection
// must not be routable to the new one.
func TestDiscoKeysAreSecretSpecific(t *testing.T) {
	client, _ := discoTestKeys(t)
	other := append([]byte(nil), discoSecret...)
	other[0] ^= 1
	otherServer, err := NewDiscoKeys(other, true)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeDisco(discoTestPackets()[0], client, 1, discoTestNow, 200)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDisco(wire, otherServer, discoTestNow); !errors.Is(err, ErrNotDisco) {
		t.Errorf("a packet from another connection was accepted: %v", err)
	}
}

func TestDiscoKeysRefuseAShortSecret(t *testing.T) {
	if _, err := NewDiscoKeys(discoSecret[:31], false); !errors.Is(err, ErrDiscoSecretTooShort) {
		t.Errorf("31-byte secret: err = %v, want ErrDiscoSecretTooShort", err)
	}
	if _, err := NewDiscoKeys(discoSecret[:32], false); err != nil {
		t.Errorf("32-byte secret: %v", err)
	}
}

// TestDiscoTagCoversTheEpochsAround checks how far the receiver's tag table
// reaches, which is what decides whether a skewed clock is diagnosable. Inside
// the table a skewed sender's packet opens and is rejected by the timestamp
// window, so it lands on a counter with the offset attached; outside it the
// packet matches no tag, and the demux hands it to QUIC as a stranger and
// counts nothing. That is why the tag has to tolerate more skew than the
// timestamp does, and how much more is the whole content of discoEpoch.
//
// The offsets are literal seconds rather than multiples of discoEpoch, because
// offsets expressed in the constant hold for every value of it -- which is how
// this test used to be written, and it passed unchanged with the epoch at 600s.
// The clock is parked on an epoch boundary (1_700_000_400 is a whole number of
// 120s, and of 60s and 600s, so a wrong constant does not get rescued by
// landing mid-epoch). From a boundary the table covers the previous epoch and
// the next, so it reaches 120s back and 240s forward, and the four offsets here
// pin the epoch to 120s from both sides.
func TestDiscoTagCoversTheEpochsAround(t *testing.T) {
	client, server := discoTestKeys(t)
	at := time.Unix(1_700_000_400, 0)
	for _, tc := range []struct {
		offset time.Duration
		inside bool
	}{
		{-120 * time.Second, true},
		{-121 * time.Second, false},
		{239 * time.Second, true},
		{240 * time.Second, false},
	} {
		wire, err := EncodeDisco(discoTestPackets()[0], client, 1, at.Add(tc.offset), 200)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeDisco(wire, server, at)
		// Every offset here is far outside the +-30s timestamp window, so a tag
		// the table holds shows up as the skew rejection and nothing else.
		if tc.inside && !errors.Is(err, ErrDiscoClockSkew) {
			t.Errorf("offset %v: err = %v, want the tag found and the timestamp rejected", tc.offset, err)
		}
		if !tc.inside && !errors.Is(err, ErrNotDisco) {
			t.Errorf("offset %v: err = %v, want ErrNotDisco", tc.offset, err)
		}
	}
}

func TestDiscoRejectsTimestampsOutsideTheWindow(t *testing.T) {
	client, server := discoTestKeys(t)
	probe := discoTestPackets()[0]
	// Within the window: accepted, in both directions of skew.
	for _, skew := range []time.Duration{-discoMaxSkew, 0, discoMaxSkew} {
		wire, err := EncodeDisco(probe, client, 1, discoTestNow.Add(skew), 200)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeDisco(wire, server, discoTestNow); err != nil {
			t.Errorf("skew %v: %v", skew, err)
		}
	}
	for _, skew := range []time.Duration{-discoMaxSkew - time.Second, discoMaxSkew + time.Second} {
		wire, err := EncodeDisco(probe, client, 1, discoTestNow.Add(skew), 200)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeDisco(wire, server, discoTestNow)
		if !errors.Is(err, ErrDiscoClockSkew) {
			t.Fatalf("skew %v: err = %v, want ErrDiscoClockSkew", skew, err)
		}
		var skewErr *DiscoSkewError
		if !errors.As(err, &skewErr) {
			t.Fatalf("skew %v: error does not carry the offset", skew)
		}
		if want := -skew; skewErr.Skew != want {
			t.Errorf("skew reported as %v, want %v", skewErr.Skew, want)
		}
	}
}

// TestDiscoRejectsTamperedBytes: every byte of the packet is either the tag,
// which is the additional data, or inside the AEAD. There is no byte an on-path
// attacker can change without the open failing.
func TestDiscoRejectsTamperedBytes(t *testing.T) {
	client, server := discoTestKeys(t)
	wire, err := EncodeDisco(discoTestPackets()[0], client, 1, discoTestNow, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []int{0, discoTagLen - 1, discoTagLen, discoTagLen + discoNonceLen, len(wire) - 1} {
		tampered := append([]byte(nil), wire...)
		tampered[off] ^= 0x01
		_, err := DecodeDisco(tampered, server, discoTestNow)
		if off < discoTagLen {
			// A changed tag is no longer one of ours, which is indistinguishable
			// from a QUIC packet and must be handed on rather than dropped.
			if !errors.Is(err, ErrNotDisco) {
				t.Errorf("byte %d: err = %v, want ErrNotDisco", off, err)
			}
			continue
		}
		if !errors.Is(err, ErrDiscoAuth) {
			t.Errorf("byte %d: err = %v, want ErrDiscoAuth", off, err)
		}
	}
}

func TestDiscoRejectsShortAndOversizedDatagrams(t *testing.T) {
	_, server := discoTestKeys(t)
	if _, err := DecodeDisco(make([]byte, discoMinWire-1), server, discoTestNow); !errors.Is(err, ErrNotDisco) {
		t.Errorf("short datagram: err = %v, want ErrNotDisco", err)
	}
	if _, err := DecodeDisco(make([]byte, discoMaxWire+1), server, discoTestNow); !errors.Is(err, ErrNotDisco) {
		t.Errorf("oversized datagram: err = %v, want ErrNotDisco", err)
	}
}

func TestDiscoRejectsUnknownVersionAndType(t *testing.T) {
	client, server := discoTestKeys(t)
	// The version and type live inside the AEAD, so producing a packet with a
	// bad one means sealing it ourselves rather than editing the wire.
	forged := forgeDiscoWire(t, client, func(plain []byte) { plain[0] = 0x03 })
	if _, err := DecodeDisco(forged, server, discoTestNow); !errors.Is(err, ErrDiscoBadVersion) {
		t.Errorf("version 0x03: err = %v, want ErrDiscoBadVersion", err)
	}
	forged = forgeDiscoWire(t, client, func(plain []byte) { plain[1] = 0x7f })
	if _, err := DecodeDisco(forged, server, discoTestNow); !errors.Is(err, ErrInvalidDiscoPacket) {
		t.Errorf("type 0x7f: err = %v, want ErrInvalidDiscoPacket", err)
	}
	// Sequence numbers start at 1. A zero is either a sender that never
	// incremented or a forgery aimed at the bottom of the replay window.
	forged = forgeDiscoWire(t, client, func(plain []byte) {
		plain[8], plain[9], plain[10], plain[11] = 0, 0, 0, 0
	})
	if _, err := DecodeDisco(forged, server, discoTestNow); !errors.Is(err, ErrInvalidDiscoPacket) {
		t.Errorf("seq 0: err = %v, want ErrInvalidDiscoPacket", err)
	}
	// A payload length that runs past the plaintext must not be believed.
	forged = forgeDiscoWire(t, client, func(plain []byte) { plain[2], plain[3] = 0xff, 0xff })
	if _, err := DecodeDisco(forged, server, discoTestNow); !errors.Is(err, ErrInvalidDiscoPacket) {
		t.Errorf("payloadLen 65535: err = %v, want ErrInvalidDiscoPacket", err)
	}
}

// forgeDiscoWire builds a packet whose plaintext has been edited after the
// header was written, which is the only way to test a check that sits inside
// the AEAD.
func forgeDiscoWire(t testing.TB, k *DiscoKeys, edit func(plain []byte)) []byte {
	t.Helper()
	wire, err := EncodeDisco(discoTestPackets()[0], k, 1, discoTestNow, 200)
	if err != nil {
		t.Fatal(err)
	}
	nonce := wire[discoTagLen : discoTagLen+discoNonceLen]
	plain, err := k.seal.(interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}).Open(nil, nonce, wire[discoTagLen+discoNonceLen:], wire[:discoTagLen])
	if err != nil {
		t.Fatal(err)
	}
	edit(plain)
	return k.seal.Seal(wire[:discoTagLen+discoNonceLen], nonce, plain, wire[:discoTagLen])
}

func TestDiscoCallMeIsBounded(t *testing.T) {
	client, _ := discoTestKeys(t)
	p := DiscoPacket{Header: DiscoHeader{Type: DiscoCallMeType}, CallMe: &DiscoCallMe{}}
	for i := 0; i <= DiscoMaxCandidates; i++ {
		p.CallMe.Candidates = append(p.CallMe.Candidates, DiscoCandidate{Addr: discoTestAddr4})
	}
	if _, err := EncodeDisco(p, client, 1, discoTestNow, 1200); !errors.Is(err, ErrInvalidDiscoPacket) {
		t.Errorf("%d candidates: err = %v, want ErrInvalidDiscoPacket", len(p.CallMe.Candidates), err)
	}
}

func TestDiscoRefusesAPacketWithoutItsPayload(t *testing.T) {
	client, _ := discoTestKeys(t)
	for _, typ := range []DiscoType{DiscoProbeType, DiscoPongType, DiscoCallMeType, DiscoBindType, DiscoBindAckType} {
		p := DiscoPacket{Header: DiscoHeader{Type: typ}}
		if _, err := EncodeDisco(p, client, 1, discoTestNow, 200); !errors.Is(err, ErrInvalidDiscoPacket) {
			t.Errorf("%s without a payload: err = %v, want ErrInvalidDiscoPacket", typ, err)
		}
	}
}

// TestProbeTokenBindsToTheAddressProbed is what lets the prober keep no table of
// probes in flight. A PONG that came back from somewhere other than the address
// the probe went to computes a different token and is dropped, so nothing has to
// remember which probes are outstanding -- and nothing can be made to remember
// more of them than it wants to.
func TestProbeTokenBindsToTheAddressProbed(t *testing.T) {
	client, _ := discoTestKeys(t)
	const tx = 987654321
	token := ProbeToken(client, discoTestAddr4, tx)
	if !CheckProbeToken(client, discoTestAddr4, tx, token) {
		t.Fatal("a token did not verify against the address it was signed for")
	}
	otherPort := netip.AddrPortFrom(discoTestAddr4.Addr(), discoTestAddr4.Port()+1)
	if CheckProbeToken(client, otherPort, tx, token) {
		t.Error("a token verified from a different port")
	}
	if CheckProbeToken(client, discoTestAddr6, tx, token) {
		t.Error("a token verified from a different address")
	}
	if CheckProbeToken(client, discoTestAddr4, tx+1, token) {
		t.Error("a token verified for a different send time")
	}
	// The probe key is per connection, so another connection cannot forge one.
	other, err := NewDiscoKeys(append([]byte("x"), discoSecret...), false)
	if err != nil {
		t.Fatal(err)
	}
	if CheckProbeToken(other, discoTestAddr4, tx, token) {
		t.Error("a token verified under another connection's key")
	}
}

// TestDiscoEncodesMappedV4AsV4 guards the Unmap in appendDiscoAddrPort.
//
// The comment on it used to claim that without the unmap the two forms of one
// address would not compare equal at the far end. They would: parseDiscoAddrPort
// unmaps what it reads, so the round trip survives either way and removing the
// Unmap left every test passing. What does not survive is the size. The same
// peer would go on the wire as 7 bytes or as 19 depending on which socket the
// kernel reported it through, so whether a CALLME fits its packet would depend
// on the peer's socket family rather than on the number of candidates -- and
// the byte a second implementation reads as the address family would disagree.
func TestDiscoEncodesMappedV4AsV4(t *testing.T) {
	mapped := netip.AddrPortFrom(netip.AddrFrom16(discoTestAddr4.Addr().As16()), discoTestAddr4.Port())
	if !mapped.Addr().Is4In6() {
		t.Fatal("the test did not build a v4-in-v6 address")
	}
	b, err := appendDiscoAddrPort(nil, mapped)
	if err != nil {
		t.Fatal(err)
	}
	// 1 family byte + 4 address bytes + 2 port bytes. Written out rather than
	// computed from the constant, so that a change to the encoding fails here.
	if len(b) != 7 {
		t.Errorf("a v4-in-v6 address encoded to %d bytes, want 7", len(b))
	}
	if b[0] != discoFamilyV4 {
		t.Errorf("family byte = 0x%02x, want the v4 family 0x%02x", b[0], discoFamilyV4)
	}
	plain, err := appendDiscoAddrPort(nil, discoTestAddr4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, plain) {
		t.Errorf("one peer encoded two ways: %x vs %x", b, plain)
	}

	// The consequence, at the size that shows it: sixteen candidates fit a
	// CALLME as v4 and do not as v4-in-v6.
	p := DiscoPacket{Header: DiscoHeader{Type: DiscoCallMeType}, CallMe: &DiscoCallMe{}}
	for range DiscoMaxCandidates {
		p.CallMe.Candidates = append(p.CallMe.Candidates, DiscoCandidate{Addr: mapped, Priority: 1})
	}
	payload, err := appendDiscoPayload(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	// 1 count byte + 16 * (7 address bytes + 1 priority byte).
	if len(payload) != 129 {
		t.Errorf("a sixteen-candidate CALLME is %d bytes, want 129", len(payload))
	}
}

// TestProbeTokenSeparatesV4FromMappedV6 guards the encoding of the address the
// token covers. A v4 address and its v4-in-v6 form are the same peer, and the
// package unmaps every address it reads off a socket, so they must produce the
// same token or a PONG would be dropped depending on how the kernel reported
// the source.
func TestProbeTokenSeparatesV4FromMappedV6(t *testing.T) {
	client, _ := discoTestKeys(t)
	mapped := netip.AddrPortFrom(netip.AddrFrom16(discoTestAddr4.Addr().As16()), discoTestAddr4.Port())
	if !mapped.Addr().Is4In6() {
		t.Fatal("the test did not build a v4-in-v6 address")
	}
	a := ProbeToken(client, discoTestAddr4, 1)
	b := ProbeToken(client, mapped, 1)
	if !bytes.Equal(a[:], b[:]) {
		t.Error("a v4 address and its v4-in-v6 form produced different tokens")
	}
}
