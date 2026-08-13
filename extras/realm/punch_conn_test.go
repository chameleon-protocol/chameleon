package realm

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPunchPacketConnPassesThroughNonPunchPackets(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)

	payload := []byte("not a punch packet")
	_, err = peer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, from, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])
	assert.Equal(t, peer.LocalAddr().String(), from.String())
}

func TestPunchPacketConnInterceptsRegisteredPunchPackets(t *testing.T) {
	meta := testPunchMetadata()
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)
	events, err := wrapped.AddPunchAttempt("attempt-1", meta)
	require.NoError(t, err)

	punchPacket, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	_, err = peer.WriteTo(punchPacket, server.LocalAddr())
	require.NoError(t, err)

	payload := []byte("quic packet")
	_, err = peer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	select {
	case ev := <-events:
		assert.Equal(t, "attempt-1", ev.AttemptID)
		assert.Equal(t, packetConnAddrPort(t, peer), ev.From)
		assert.Equal(t, PunchPacketHello, ev.Packet.Type)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for punch event")
	}
}

func TestPunchPacketConnRemovePunchAttempt(t *testing.T) {
	meta := testPunchMetadata()
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)
	events, err := wrapped.AddPunchAttempt("attempt-1", meta)
	require.NoError(t, err)
	wrapped.RemovePunchAttempt("attempt-1")

	punchPacket, err := EncodePunchPacket(PunchPacketAck, meta)
	require.NoError(t, err)
	_, err = peer.WriteTo(punchPacket, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, punchPacket, buf[:n])

	select {
	case ev := <-events:
		t.Fatalf("unexpected punch event: %+v", ev)
	default:
	}
}

func TestPunchPacketConnRejectsBadAttempts(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)

	_, err = wrapped.AddPunchAttempt("", testPunchMetadata())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchAttempt), "got %v", err)

	_, err = wrapped.AddPunchAttempt("attempt-1", PunchMetadata{
		Nonce: "not-hex",
		Obfs:  testPunchMetadata().Obfs,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket), "got %v", err)

	_, err = wrapped.AddPunchAttempt("attempt-1", testPunchMetadata())
	require.NoError(t, err)
	_, err = wrapped.AddPunchAttempt("attempt-1", testPunchMetadata())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchAttempt), "got %v", err)
}

func TestPunchPacketConnCloseClosesUnderlyingConn(t *testing.T) {
	server := listenUDP4(t)
	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)

	require.NoError(t, wrapped.Close())
	_, _, err = wrapped.ReadFrom(make([]byte, 1))
	require.Error(t, err)
}

func TestNewPunchPacketConnRejectsNilConn(t *testing.T) {
	_, err := NewPunchPacketConn(nil, 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchAttempt), "got %v", err)
}

func TestPunchPacketConnDoesNotExposePunchBytesToReader(t *testing.T) {
	meta := testPunchMetadata()
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)
	_, err = wrapped.AddPunchAttempt("attempt-1", meta)
	require.NoError(t, err)

	punchPacket, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	_, err = peer.WriteTo(punchPacket, server.LocalAddr())
	require.NoError(t, err)

	payload := []byte("next packet")
	_, err = peer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(punchPacket, buf[:n]))
	assert.Equal(t, payload, buf[:n])
}

func TestPunchPacketConnInterceptsSTUNPackets(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)

	txID := stun.NewTransactionID()
	mapped := netip.MustParseAddrPort("203.0.113.10:4433")
	response := buildSTUNBindingResponse(t, txID, netip.AddrPort{}, mapped)
	_, err = peer.WriteTo(response, server.LocalAddr())
	require.NoError(t, err)

	payload := []byte("quic packet")
	_, err = peer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	select {
	case ev := <-wrapped.STUNEvents():
		assert.Equal(t, txID, ev.Message.TransactionID)
		assert.Equal(t, mapped, ev.Addr)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for STUN event")
	}
}

var _ net.PacketConn = (*PunchPacketConn)(nil)

// Compile-time check: PunchPacketConn must expose UDP-specific methods so
// quic-go and obfs (above us in the stack) can keep DF/PMTU detection and
// recv/send buffer sizing.
var _ interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
} = (*PunchPacketConn)(nil)

func TestPunchPacketConnExposesUDPMethods(t *testing.T) {
	udp := listenUDP4(t)
	defer udp.Close()

	wrapped, err := NewPunchPacketConn(udp, 1)
	require.NoError(t, err)

	rc, err := wrapped.SyscallConn()
	require.NoError(t, err)
	require.NotNil(t, rc)

	require.NoError(t, wrapped.SetReadBuffer(1<<20))
	require.NoError(t, wrapped.SetWriteBuffer(1<<20))
}

func TestPunchPacketConnUnsupportedWhenNotUDP(t *testing.T) {
	wrapped, err := NewPunchPacketConn(&nonUDPPacketConn{}, 1)
	require.NoError(t, err)

	_, err = wrapped.SyscallConn()
	assert.ErrorIs(t, err, errors.ErrUnsupported)
	assert.ErrorIs(t, wrapped.SetReadBuffer(1<<20), errors.ErrUnsupported)
	assert.ErrorIs(t, wrapped.SetWriteBuffer(1<<20), errors.ErrUnsupported)
}

type nonUDPPacketConn struct{}

func (nonUDPPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (nonUDPPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (nonUDPPacketConn) Close() error                           { return nil }
func (nonUDPPacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (nonUDPPacketConn) SetDeadline(time.Time) error            { return nil }
func (nonUDPPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (nonUDPPacketConn) SetWriteDeadline(time.Time) error       { return nil }

// memPacketConn returns a fixed payload on every ReadFrom call. Used to
// isolate PunchPacketConn's per-packet demux cost from syscall/network noise.
type memPacketConn struct {
	payload []byte
	addr    net.Addr
}

func (c *memPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, c.payload), c.addr, nil
}
func (c *memPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *memPacketConn) Close() error                              { return nil }
func (c *memPacketConn) LocalAddr() net.Addr                       { return c.addr }
func (c *memPacketConn) SetDeadline(time.Time) error               { return nil }
func (c *memPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (c *memPacketConn) SetWriteDeadline(time.Time) error          { return nil }

func quicLikePayload(size int) []byte {
	p := make([]byte, size)
	// Top two bits set marks this as a QUIC long-header packet, which makes
	// stun.IsMessage immediately return false (cheapest fast path).
	p[0] = 0xc0
	return p
}

// BenchmarkBaselineReadFrom is the underlying memPacketConn alone, for a
// reference number to subtract from the wrapped benchmarks.
func BenchmarkBaselineReadFrom(b *testing.B) {
	underlying := &memPacketConn{payload: quicLikePayload(1200), addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}}
	buf := make([]byte, 1500)
	b.SetBytes(int64(len(underlying.payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := underlying.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// testPunchMetadataN returns metadata unique to i, for tests that need many
// in-flight attempts.
func testPunchMetadataN(i int) PunchMetadata {
	return PunchMetadata{
		Nonce: fmt.Sprintf("%032x", i),
		Obfs:  fmt.Sprintf("%064x", i),
	}
}

func addPunchAttempts(tb testing.TB, conn *PunchPacketConn, n int) []<-chan PunchPacketEvent {
	tb.Helper()
	events := make([]<-chan PunchPacketEvent, n)
	for i := range n {
		ch, err := conn.AddPunchAttempt(fmt.Sprintf("attempt-%d", i), testPunchMetadataN(i))
		require.NoError(tb, err)
		events[i] = ch
	}
	return events
}

// With punching now permanent, many attempts can be in flight at once. A packet
// must reach exactly the attempt it belongs to, whatever the neighbours are.
func TestPunchPacketConnRoutesAmongManyAttempts(t *testing.T) {
	const attempts = 512
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 4)
	require.NoError(t, err)
	events := addPunchAttempts(t, wrapped, attempts)
	pumpPunchPacketConn(t, wrapped)

	for _, i := range []int{0, 1, attempts / 2, attempts - 1} {
		packet, err := EncodePunchPacket(PunchPacketHello, testPunchMetadataN(i))
		require.NoError(t, err)
		_, err = peer.WriteTo(packet, server.LocalAddr())
		require.NoError(t, err)

		select {
		case ev := <-events[i]:
			assert.Equal(t, fmt.Sprintf("attempt-%d", i), ev.AttemptID)
			assert.Equal(t, PunchPacketHello, ev.Packet.Type)
		case <-time.After(time.Second):
			t.Fatalf("attempt %d never got its packet", i)
		}
	}

	for i, ch := range events {
		select {
		case ev := <-ch:
			t.Fatalf("attempt %d got a packet meant for %s", i, ev.AttemptID)
		default:
		}
	}
}

func TestPunchPacketConnPassesUnregisteredPunchPacketThrough(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 4)
	require.NoError(t, err)
	events := addPunchAttempts(t, wrapped, 64)

	// Valid punch packet, but for metadata nobody registered: it is not ours,
	// so it belongs to the reader above like any other unknown packet.
	packet, err := EncodePunchPacket(PunchPacketHello, testPunchMetadataN(1000))
	require.NoError(t, err)
	_, err = peer.WriteTo(packet, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, packet, buf[:n])
	for i, ch := range events {
		select {
		case <-ch:
			t.Fatalf("attempt %d claimed a packet it cannot decode", i)
		default:
		}
	}
}

// A tag collision must not lose the packet: the bucket is walked, so both
// attempts still get exactly their own traffic.
func TestPunchPacketConnHandlesTagCollisions(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 4)
	require.NoError(t, err)
	metaA := testPunchMetadataN(1)
	metaB := testPunchMetadataN(2)
	eventsA, err := wrapped.AddPunchAttempt("attempt-a", metaA)
	require.NoError(t, err)
	eventsB, err := wrapped.AddPunchAttempt("attempt-b", metaB)
	require.NoError(t, err)

	// Force the collision the index has to survive: both attempts land in one
	// bucket, the wrong one first, so the lookup has to walk past it. Real
	// attempts collide with probability 2^-32 per pair.
	keyA, err := newPunchKey(metaA)
	require.NoError(t, err)
	keyB, err := newPunchKey(metaB)
	require.NoError(t, err)
	wrapped.mu.Lock()
	attemptB := wrapped.attempts["attempt-b"]
	delete(wrapped.byTag, keyB.tag)
	wrapped.byTag[keyA.tag] = append([]*punchAttempt{attemptB}, wrapped.byTag[keyA.tag]...)
	wrapped.mu.Unlock()

	pumpPunchPacketConn(t, wrapped)
	packet, err := EncodePunchPacket(PunchPacketHello, metaA)
	require.NoError(t, err)
	_, err = peer.WriteTo(packet, server.LocalAddr())
	require.NoError(t, err)

	select {
	case ev := <-eventsA:
		assert.Equal(t, "attempt-a", ev.AttemptID)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the colliding attempt's packet")
	}
	select {
	case ev := <-eventsB:
		t.Fatalf("colliding attempt stole the packet: %+v", ev)
	default:
	}
}

// BenchmarkPunchPacketConnReadFrom measures what every inbound packet costs
// while punch attempts are registered. It is flat in the number of attempts by
// design: an attacker spraying packets must not be able to make each one cost
// a decryption per in-flight attempt.
func BenchmarkPunchPacketConnReadFrom(b *testing.B) {
	for _, attempts := range []int{0, 1, 64, 1024} {
		b.Run(fmt.Sprintf("attempts=%d", attempts), func(b *testing.B) {
			underlying := &memPacketConn{payload: quicLikePayload(1200), addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}}
			conn, err := NewPunchPacketConn(underlying, 1)
			require.NoError(b, err)
			addPunchAttempts(b, conn, attempts)
			buf := make([]byte, 1500)
			b.SetBytes(int64(len(underlying.payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := conn.ReadFrom(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPunchPacketConnReadFromSprayed is the DoS case: packets that are the
// right length for a punch packet but decode for nobody.
func BenchmarkPunchPacketConnReadFromSprayed(b *testing.B) {
	for _, attempts := range []int{0, 1, 64, 1024} {
		b.Run(fmt.Sprintf("attempts=%d", attempts), func(b *testing.B) {
			sprayed, err := EncodePunchPacket(PunchPacketHello, testPunchMetadataN(1<<20))
			require.NoError(b, err)
			underlying := &memPacketConn{payload: sprayed, addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}}
			conn, err := NewPunchPacketConn(underlying, 1)
			require.NoError(b, err)
			addPunchAttempts(b, conn, attempts)
			buf := make([]byte, 1500)
			b.SetBytes(int64(len(underlying.payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := conn.ReadFrom(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
