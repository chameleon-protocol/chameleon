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

package realm

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A rendezvous server knows the punch metadata, so it can forge packets that
// decode fine. The source address is what keeps it from choosing the QUIC peer.
func TestPunchIgnoresSourceOutsideCandidates(t *testing.T) {
	meta := testPunchMetadata()
	client := listenUDP4(t)
	defer client.Close()
	announced := listenUDP4(t)
	defer announced.Close()
	forger := listenUDP4(t)
	defer forger.Close()

	clientAddr := packetConnAddrPort(t, client)
	stop := floodHello(t, forger, clientAddr, meta)
	defer stop()

	_, err := Punch(context.Background(), client, []netip.AddrPort{clientAddr},
		[]netip.AddrPort{packetConnAddrPort(t, announced)}, meta, PunchConfig{
			Timeout:  300 * time.Millisecond,
			Interval: 10 * time.Millisecond,
		})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPunchTimeout), "got %v", err)

	// An untrusted source must not even learn that its metadata was right.
	require.NoError(t, forger.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	buf := make([]byte, punchMaxWireLen)
	_, _, err = forger.ReadFrom(buf)
	require.Error(t, err)
	assert.True(t, isTimeout(err), "got %v", err)
}

// A peer behind a symmetric NAT is announced at ports next to the one it will
// actually use, and the predicted ports are candidates like any other.
func TestPunchAcceptsPredictedSymmetricNATPort(t *testing.T) {
	meta := testPunchMetadata()
	client := listenUDP4(t)
	defer client.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	clientAddr := packetConnAddrPort(t, client)
	peerAddr := packetConnAddrPort(t, peer)
	// Announce two consecutive ports below the real one: expansion covers the
	// announced range plus symmetricNATExtraPorts, so the real port is in it.
	announced := []netip.AddrPort{
		netip.AddrPortFrom(peerAddr.Addr(), peerAddr.Port()-2),
		netip.AddrPortFrom(peerAddr.Addr(), peerAddr.Port()-1),
	}
	ackDone := ackOnHello(t, peer, meta)

	result, err := Punch(context.Background(), client, []netip.AddrPort{clientAddr}, announced, meta, PunchConfig{
		Timeout:  time.Second,
		Interval: 10 * time.Millisecond,
	})
	require.NoError(t, err)
	assert.Equal(t, peerAddr, result.PeerAddr)
	<-ackDone
}

func TestPunchCandidateHostsPolicyAcceptsUnpredictedPort(t *testing.T) {
	meta := testPunchMetadata()
	client := listenUDP4(t)
	defer client.Close()
	peer := listenUDP4(t)
	defer peer.Close()
	announced := listenUDP4(t)
	defer announced.Close()

	clientAddr := packetConnAddrPort(t, client)
	peerAddr := packetConnAddrPort(t, peer)
	stop := floodHello(t, peer, clientAddr, meta)
	defer stop()

	result, err := Punch(context.Background(), client, []netip.AddrPort{clientAddr},
		[]netip.AddrPort{packetConnAddrPort(t, announced)}, meta, PunchConfig{
			Timeout:      time.Second,
			Interval:     10 * time.Millisecond,
			SourcePolicy: PunchSourceCandidateHosts,
		})
	require.NoError(t, err)
	assert.Equal(t, peerAddr, result.PeerAddr)
}

func TestPunchRejectsUnknownSourcePolicy(t *testing.T) {
	client := listenUDP4(t)
	defer client.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	_, err := Punch(context.Background(), client, []netip.AddrPort{packetConnAddrPort(t, client)},
		[]netip.AddrPort{packetConnAddrPort(t, peer)}, testPunchMetadata(), PunchConfig{
			SourcePolicy: PunchSourcePolicy(42),
		})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchConfig), "got %v", err)
}

// The responder cannot predict the source port of a symmetric NAT peer, so it
// stays permissive by default.
func TestServerPuncherAcceptsSourceOutsideCandidates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meta := testPunchMetadata()
	server, wrapped, puncher := newTestServerPuncher(t, ctx)
	defer server.Close()
	pumpPunchPacketConn(wrapped)
	client := listenUDP4(t)
	defer client.Close()

	serverAddr := packetConnAddrPort(t, server)
	clientAddr := packetConnAddrPort(t, client)
	unrelated := netip.AddrPortFrom(serverAddr.Addr(), 9)

	done := make(chan punchResponse, 1)
	go func() {
		r, err := puncher.Respond(ctx, "attempt-1", []netip.AddrPort{serverAddr}, []netip.AddrPort{unrelated}, meta, PunchConfig{
			Timeout:  time.Second,
			Interval: 10 * time.Millisecond,
		})
		done <- punchResponse{result: r, err: err}
	}()
	time.Sleep(10 * time.Millisecond)
	sendHello(t, client, server.LocalAddr(), meta)

	resp := <-done
	require.NoError(t, resp.err)
	assert.Equal(t, clientAddr, resp.result.PeerAddr)
}

func TestServerPuncherCandidatePolicyRejectsSourceOutsideCandidates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meta := testPunchMetadata()
	server, wrapped, puncher := newTestServerPuncher(t, ctx)
	defer server.Close()
	pumpPunchPacketConn(wrapped)
	client := listenUDP4(t)
	defer client.Close()

	serverAddr := packetConnAddrPort(t, server)
	unrelated := netip.AddrPortFrom(serverAddr.Addr(), 9)

	done := make(chan punchResponse, 1)
	go func() {
		r, err := puncher.Respond(ctx, "attempt-1", []netip.AddrPort{serverAddr}, []netip.AddrPort{unrelated}, meta, PunchConfig{
			Timeout:      200 * time.Millisecond,
			Interval:     10 * time.Millisecond,
			SourcePolicy: PunchSourceCandidates,
		})
		done <- punchResponse{result: r, err: err}
	}()
	time.Sleep(10 * time.Millisecond)
	sendHello(t, client, server.LocalAddr(), meta)

	resp := <-done
	require.Error(t, resp.err)
	assert.True(t, errors.Is(resp.err, ErrPunchTimeout), "got %v", resp.err)
}

func TestCandidatePunchAddrsRejectsUnpunchableTargets(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("0.0.0.0:4433"),
		netip.MustParseAddrPort("224.0.0.1:4433"),
		netip.MustParseAddrPort("127.0.0.1:4433"),
		netip.MustParseAddrPort("198.51.100.20:0"),
		netip.MustParseAddrPort("198.51.100.20:4433"),
	}

	candidates := candidatePunchAddrs(local, peer, AddrFamilyAny)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:4433")}, candidates)
}

func TestCandidatePunchAddrsKeepsLoopbackForLoopbackPeers(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1234")}
	peer := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:4433")}

	candidates := candidatePunchAddrs(local, peer, AddrFamilyAny)
	assert.Equal(t, peer, candidates)
}

func TestCandidatePunchAddrsUnmapsV4InV6(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("[::ffff:198.51.100.20]:4433"),
		netip.MustParseAddrPort("198.51.100.20:4433"),
	}

	candidates := candidatePunchAddrs(local, peer, AddrFamilyAny)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:4433")}, candidates)
}

func TestCandidatePunchAddrsCapsCandidateCount(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")}
	var peer []netip.AddrPort
	for i := 0; i < 40; i++ {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 40000)
		peer = append(peer, addr, netip.AddrPortFrom(addr.Addr(), 40001))
	}

	candidates := candidatePunchAddrs(local, peer, AddrFamilyAny)
	assert.LessOrEqual(t, len(candidates), maxPunchCandidates)
	assert.NotEmpty(t, candidates)
}

// floodHello keeps sending hello packets to addr until the returned function is
// called, so a punch attempt cannot miss them by timing.
func floodHello(t *testing.T, conn net.PacketConn, addr netip.AddrPort, meta PunchMetadata) func() {
	t.Helper()
	packet, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := conn.WriteTo(packet, udpAddrFromAddrPort(addr)); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

// ackOnHello answers the first hello conn receives, the way a punching peer
// would.
func ackOnHello(t *testing.T, conn net.PacketConn, meta PunchMetadata) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, punchMaxWireLen)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			packet, err := DecodePunchPacket(buf[:n], meta)
			if err != nil || packet.Type != PunchPacketHello {
				continue
			}
			ack, err := EncodePunchPacket(PunchPacketAck, meta)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(ack, addr)
			return
		}
	}()
	return done
}
