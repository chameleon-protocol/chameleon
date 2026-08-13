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

// The point of the rework: punching is not a phase that ends when QUIC starts.
// A punch must run to completion on a socket whose reads belong to the data
// plane, and it must be repeatable afterwards — that is what a re-punch after a
// network change needs.
func TestPunchCoexistsWithDataPlane(t *testing.T) {
	meta := testPunchMetadata()
	local := listenUDP4(t)
	defer local.Close()
	demux, err := NewPunchPacketConn(local, 8)
	require.NoError(t, err)
	puncher, err := NewPuncher(demux)
	require.NoError(t, err)

	peer := listenUDP4(t)
	defer peer.Close()
	sender := listenUDP4(t)
	defer sender.Close()

	// The data plane owns the reads, the way quic-go does once it has the
	// socket.
	data := make(chan string, 64)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := demux.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case data <- string(buf[:n]):
			default:
			}
		}
	}()
	stopData := repeatSend(t, sender, local.LocalAddr(), []byte("quic packet"))
	defer stopData()
	requireDataFlowing(t, data)

	localAddr := packetConnAddrPort(t, local)
	peerAddr := packetConnAddrPort(t, peer)
	config := PunchConfig{Timeout: 2 * time.Second, Interval: 10 * time.Millisecond}

	first := ackOnHello(t, peer, meta)
	result, err := puncher.Punch(context.Background(), "attempt-1", []netip.AddrPort{localAddr}, []netip.AddrPort{peerAddr}, meta, config)
	require.NoError(t, err)
	assert.Equal(t, peerAddr, result.PeerAddr)
	<-first

	// Again, on the same live socket. Before the rework this was impossible:
	// the punch owned conn reads, so it had to run before QUIC existed.
	second := ackOnHello(t, peer, meta)
	result, err = puncher.Punch(context.Background(), "attempt-2", []netip.AddrPort{localAddr}, []netip.AddrPort{peerAddr}, meta, config)
	require.NoError(t, err)
	assert.Equal(t, peerAddr, result.PeerAddr)
	<-second

	// The data plane never lost the socket.
	requireDataFlowing(t, data)
}

// Punch keeps working when handed the demux conn, which is how a caller that
// has not moved to Puncher yet still gets a non-exclusive punch.
func TestPunchOnDemuxConnDoesNotOwnReads(t *testing.T) {
	meta := testPunchMetadata()
	local := listenUDP4(t)
	defer local.Close()
	demux, err := NewPunchPacketConn(local, 8)
	require.NoError(t, err)
	peer := listenUDP4(t)
	defer peer.Close()
	sender := listenUDP4(t)
	defer sender.Close()

	data := make(chan string, 64)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := demux.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case data <- string(buf[:n]):
			default:
			}
		}
	}()
	stopData := repeatSend(t, sender, local.LocalAddr(), []byte("quic packet"))
	defer stopData()

	done := ackOnHello(t, peer, meta)
	result, err := Punch(context.Background(), demux, []netip.AddrPort{packetConnAddrPort(t, local)},
		[]netip.AddrPort{packetConnAddrPort(t, peer)}, meta, PunchConfig{
			Timeout:  2 * time.Second,
			Interval: 10 * time.Millisecond,
		})
	require.NoError(t, err)
	assert.Equal(t, packetConnAddrPort(t, peer), result.PeerAddr)
	<-done
	requireDataFlowing(t, data)
}

// Before QUIC exists nobody reads the socket, so the pump stands in for it.
// Handing the socket over afterwards must not lose what arrived in between.
func TestPunchPacketConnPumpHandsOverQueuedPackets(t *testing.T) {
	meta := testPunchMetadata()
	local := listenUDP4(t)
	defer local.Close()
	demux, err := NewPunchPacketConn(local, 4)
	require.NoError(t, err)
	events, err := demux.AddPunchAttempt("attempt-1", meta)
	require.NoError(t, err)
	peer := listenUDP4(t)
	defer peer.Close()

	demux.StartPump()
	hello, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	_, err = peer.WriteTo(hello, local.LocalAddr())
	require.NoError(t, err)
	select {
	case ev := <-events:
		assert.Equal(t, PunchPacketHello, ev.Packet.Type)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for a punch event while pumping")
	}

	_, err = peer.WriteTo([]byte("quic packet"), local.LocalAddr())
	require.NoError(t, err)
	// Let the pump pick it up before the handover.
	time.Sleep(50 * time.Millisecond)
	demux.StopPump()

	buf := make([]byte, 1500)
	require.NoError(t, local.SetReadDeadline(time.Now().Add(time.Second)))
	n, from, err := demux.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "quic packet", string(buf[:n]))
	assert.Equal(t, peer.LocalAddr().String(), from.String())
	require.NoError(t, local.SetReadDeadline(time.Time{}))
}

// A queued data packet must arrive whole: a full-size QUIC packet is bigger
// than any punch packet, and handing the reader a truncated one is worse than
// having dropped it.
func TestPunchPacketConnPumpQueuesFullSizePackets(t *testing.T) {
	local := listenUDP4(t)
	defer local.Close()
	demux, err := NewPunchPacketConn(local, 4)
	require.NoError(t, err)
	peer := listenUDP4(t)
	defer peer.Close()

	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	demux.StartPump()
	_, err = peer.WriteTo(payload, local.LocalAddr())
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	demux.StopPump()

	buf := make([]byte, 1500)
	n, _, err := demux.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])
}

func TestPunchPacketConnStopPumpClearsReadDeadline(t *testing.T) {
	local := listenUDP4(t)
	defer local.Close()
	demux, err := NewPunchPacketConn(local, 4)
	require.NoError(t, err)
	peer := listenUDP4(t)
	defer peer.Close()

	demux.StartPump()
	demux.StopPump()

	// A leftover deadline from the pump would make this read fail instead of
	// blocking until the packet shows up.
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, _ = peer.WriteTo([]byte("quic packet"), local.LocalAddr())
	}()
	buf := make([]byte, 1500)
	n, _, err := demux.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "quic packet", string(buf[:n]))
}

func TestPuncherRejectsBadAttemptID(t *testing.T) {
	local := listenUDP4(t)
	defer local.Close()
	demux, err := NewPunchPacketConn(local, 4)
	require.NoError(t, err)
	puncher, err := NewPuncher(demux)
	require.NoError(t, err)

	_, err = puncher.Punch(context.Background(), "", []netip.AddrPort{packetConnAddrPort(t, local)},
		[]netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:4433")}, testPunchMetadata(), PunchConfig{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPunchAttempt)
}

func TestPuncherRejectsDuplicateAttemptID(t *testing.T) {
	meta := testPunchMetadata()
	local := listenUDP4(t)
	defer local.Close()
	demux, err := NewPunchPacketConn(local, 4)
	require.NoError(t, err)
	puncher, err := NewPuncher(demux)
	require.NoError(t, err)
	peer := listenUDP4(t)
	defer peer.Close()

	_, err = demux.AddPunchAttempt("attempt-1", meta)
	require.NoError(t, err)

	_, err = puncher.Punch(context.Background(), "attempt-1", []netip.AddrPort{packetConnAddrPort(t, local)},
		[]netip.AddrPort{packetConnAddrPort(t, peer)}, meta, PunchConfig{Timeout: 50 * time.Millisecond})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPunchAttempt)
}

// An attempt must release its slot when it finishes, or a re-punch with the
// same identity (a retry after a network change) would be refused.
func TestPuncherReleasesAttemptID(t *testing.T) {
	meta := testPunchMetadata()
	local := listenUDP4(t)
	defer local.Close()
	demux, err := NewPunchPacketConn(local, 4)
	require.NoError(t, err)
	demux.StartPump()
	defer demux.StopPump()
	puncher, err := NewPuncher(demux)
	require.NoError(t, err)
	peer := listenUDP4(t)
	defer peer.Close()

	config := PunchConfig{Timeout: 50 * time.Millisecond, Interval: 10 * time.Millisecond}
	addrs := []netip.AddrPort{packetConnAddrPort(t, local)}
	peers := []netip.AddrPort{packetConnAddrPort(t, peer)}
	_, err = puncher.Punch(context.Background(), "attempt-1", addrs, peers, meta, config)
	assert.ErrorIs(t, err, ErrPunchTimeout)
	_, err = puncher.Punch(context.Background(), "attempt-1", addrs, peers, meta, config)
	assert.ErrorIs(t, err, ErrPunchTimeout)
}

func TestServerPuncherStopsWithItsContext(t *testing.T) {
	meta := testPunchMetadata()
	ctx, cancel := context.WithCancel(context.Background())
	server, wrapped, puncher := newTestServerPuncher(t, ctx)
	defer server.Close()
	pumpPunchPacketConn(t, wrapped)
	peer := listenUDP4(t)
	defer peer.Close()

	done := make(chan error, 1)
	go func() {
		_, err := puncher.Respond(context.Background(), "attempt-1", []netip.AddrPort{packetConnAddrPort(t, server)},
			[]netip.AddrPort{packetConnAddrPort(t, peer)}, meta, PunchConfig{Timeout: 10 * time.Second, Interval: 10 * time.Millisecond})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
	case <-time.After(time.Second):
		t.Fatal("attempt outlived the puncher context")
	}
}

// repeatSend keeps a packet flowing to addr until the returned function is
// called, standing in for a data plane that never stops.
func repeatSend(t *testing.T, conn net.PacketConn, addr net.Addr, payload []byte) func() {
	t.Helper()
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
			if _, err := conn.WriteTo(payload, addr); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

func requireDataFlowing(t *testing.T, data <-chan string) {
	t.Helper()
	select {
	case got := <-data:
		require.Equal(t, "quic packet", got)
	case <-time.After(2 * time.Second):
		t.Fatal("the data plane stopped receiving packets")
	}
}
