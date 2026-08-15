package realm

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingPacketConn keeps the length of everything written to it.
type recordingPacketConn struct {
	addr net.Addr

	mu   sync.Mutex
	lens []int
}

func (c *recordingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, c.addr, net.ErrClosed
}

func (c *recordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	c.lens = append(c.lens, len(p))
	c.mu.Unlock()
	return len(p), nil
}
func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) LocalAddr() net.Addr              { return c.addr }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingPacketConn) written() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.lens...)
}
func (c *recordingPacketConn) reset() { c.mu.Lock(); defer c.mu.Unlock(); c.lens = nil }

func newRecordingPunchConn(tb testing.TB) (*recordingPacketConn, *PunchPacketConn) {
	tb.Helper()
	rec := &recordingPacketConn{addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}}
	conn, err := NewPunchPacketConn(rec, testMask, 1)
	require.NoError(tb, err)
	return rec, conn
}

// A punch packet takes its length from the lengths this socket is already
// sending, because sealing does not hide length and a distribution of its own
// is a per-packet distinguisher. The two lengths here are the ones measured on
// a loaded connection: 1439 without an obfuscator, 1471 with salamander v2.
func TestPunchPacketLengthComesFromTheSocket(t *testing.T) {
	rec, conn := newRecordingPunchConn(t)
	key, err := newPunchKey(testPunchMetadata(), testMask)
	require.NoError(t, err)
	peer := netip.MustParseAddrPort("192.0.2.2:4433")

	for range 8 {
		_, err := conn.WriteTo(make([]byte, 1439), rec.addr)
		require.NoError(t, err)
		_, err = conn.WriteTo(make([]byte, 1471), rec.addr)
		require.NoError(t, err)
	}
	rec.reset()

	for range 64 {
		sendPunchPacket(conn, peer, key, PunchPacketHello, 0)
	}
	sent := rec.written()
	require.Len(t, sent, 64)
	seen := map[int]int{}
	for _, n := range sent {
		require.Containsf(t, []int{1439, 1471}, n,
			"punch packet went out at %d bytes, which nothing on this socket has sent", n)
		seen[n]++
	}
	assert.Len(t, seen, 2, "every punch packet copied the same sample: %v", seen)
}

// The sampler must not learn from punch packets. If it did, the first punch
// packet's guessed length would become the sample the next one copies, and the
// distribution would close over itself instead of following the connection.
func TestPunchPacketsAreNotSamples(t *testing.T) {
	rec, conn := newRecordingPunchConn(t)
	key, err := newPunchKey(testPunchMetadata(), testMask)
	require.NoError(t, err)
	peer := netip.MustParseAddrPort("192.0.2.2:4433")

	for range 32 {
		sendPunchPacket(conn, peer, key, PunchPacketHello, 0)
	}
	require.Len(t, rec.written(), 32)
	assert.Zero(t, conn.lengths.count.Load(), "punch packets fed the length sampler")

	// One real packet, and from then on every punch packet must be that length:
	// with a single sample there is nothing else to copy.
	_, err = conn.WriteTo(make([]byte, 1471), rec.addr)
	require.NoError(t, err)
	rec.reset()
	for range 32 {
		sendPunchPacket(conn, peer, key, PunchPacketHello, 0)
	}
	for _, n := range rec.written() {
		assert.Equal(t, 1471, n)
	}
}

// The responder is not exempt from the fallback, and the code comments say
// where it is not: a realm server's socket writes nothing but STUN binding
// requests until its first QUIC connection exists, and a binding request is 20
// bytes, well under punchMinWireLen. So the first punch response after a
// restart is padded to a guess, exactly like an initiator's, and the design
// document must not claim the responder is at 0% without saying so.
//
// This pins the window rather than the fix. Once one real datagram has gone
// out, the fallback is unreachable.
func TestPunchResponderFallsBackUntilTheSocketHasSentQUIC(t *testing.T) {
	rec, conn := newRecordingPunchConn(t)
	key, err := newPunchKey(testPunchMetadata(), testMask)
	require.NoError(t, err)
	peer := netip.MustParseAddrPort("192.0.2.2:4433")

	// What a responder has sent before any client reaches it: STUN, and the
	// binding request is the smallest of it.
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	require.Len(t, req.Raw, 20)
	_, err = conn.WriteTo(req.Raw, rec.addr)
	require.NoError(t, err)
	assert.Zero(t, conn.lengths.count.Load(), "a STUN binding request became a length sample")

	rec.reset()
	for range 64 {
		sendPunchPacket(conn, peer, key, PunchPacketHello, 0)
	}
	for _, n := range rec.written() {
		assert.GreaterOrEqual(t, n, punchFallbackMinLen)
		assert.LessOrEqual(t, n, punchFallbackMaxLen)
	}

	// One QUIC datagram closes the window for good.
	_, err = conn.WriteTo(make([]byte, 1471), rec.addr)
	require.NoError(t, err)
	rec.reset()
	for range 64 {
		sendPunchPacket(conn, peer, key, PunchPacketHello, 0)
	}
	for _, n := range rec.written() {
		assert.Equal(t, 1471, n, "a responder with a sample still guessed")
	}
}

// Lengths a punch packet cannot take are not samples either: a QUIC keep-alive
// smaller than the punch header would otherwise pin every punch packet to the
// header length, which is a beacon of its own.
func TestPunchLengthSamplerSkipsUnusableLengths(t *testing.T) {
	rec, conn := newRecordingPunchConn(t)
	key, err := newPunchKey(testPunchMetadata(), testMask)
	require.NoError(t, err)
	peer := netip.MustParseAddrPort("192.0.2.2:4433")

	_, err = conn.WriteTo(make([]byte, punchMinWireLen-1), rec.addr)
	require.NoError(t, err)
	_, err = conn.WriteTo(make([]byte, punchMaxWireLen+1), rec.addr)
	require.NoError(t, err)
	assert.Zero(t, conn.lengths.count.Load())

	// The modal wire length of a salamander v2 server is 1473 bytes, captured.
	// The ceiling used to sit at 1472, so the sampler threw away the one length
	// a responder most needs to copy and padded from the fallback band instead,
	// on a socket that was carrying exactly the right lengths to imitate.
	_, err = conn.WriteTo(make([]byte, 1473), rec.addr)
	require.NoError(t, err)
	n, ok := conn.lengths.sample()
	require.True(t, ok, "a datagram this socket sent did not become a sample")
	assert.Equal(t, 1473, n)

	rec.reset()
	for range 16 {
		sendPunchPacket(conn, peer, key, PunchPacketHello, 0)
	}
	for _, n := range rec.written() {
		assert.GreaterOrEqual(t, n, 1200)
		assert.LessOrEqual(t, n, 1473)
	}
}

// An initiator has no sample, but the wiring can name the length its connection
// will mostly send at. Given that, every punch packet takes it, so the packets
// sit in the biggest length bucket on the path instead of a band that a
// classifier trained on the deployment picks out.
func TestPunchPacketTakesThePadToWireLen(t *testing.T) {
	rec, conn := newRecordingPunchConn(t)
	key, err := newPunchKey(testPunchMetadata(), testMask)
	require.NoError(t, err)
	peer := netip.MustParseAddrPort("192.0.2.2:4433")

	// 1471 is the modal wire length of a real client under salamander v2, taken
	// from a capture of a loaded connection where it was 60% of what it sent.
	const modal = 1471
	for range 64 {
		sendPunchPacket(conn, peer, key, PunchPacketHello, modal)
	}
	for _, n := range rec.written() {
		assert.Equal(t, modal, n, "a punch packet ignored the length it was given")
	}

	// A sample beats it: a length this socket has sent is better evidence than
	// one it is about to send.
	_, err = conn.WriteTo(make([]byte, 1471), rec.addr)
	require.NoError(t, err)
	rec.reset()
	for range 32 {
		sendPunchPacket(conn, peer, key, PunchPacketHello, modal)
	}
	for _, n := range rec.written() {
		assert.Equal(t, 1471, n, "a sampled length lost to the hint")
	}
}

// A length a punch packet cannot be built at is refused rather than clamped:
// padding to an impossible target would be worse than the band it replaces.
func TestPunchPacketRejectsUnusablePadToWireLen(t *testing.T) {
	rec, conn := newRecordingPunchConn(t)
	key, err := newPunchKey(testPunchMetadata(), testMask)
	require.NoError(t, err)
	peer := netip.MustParseAddrPort("192.0.2.2:4433")

	for _, bad := range []int{punchMinWireLen - 1, punchMaxWireLen + 1} {
		rec.reset()
		for range 16 {
			sendPunchPacket(conn, peer, key, PunchPacketHello, bad)
		}
		for _, n := range rec.written() {
			assert.GreaterOrEqual(t, n, punchFallbackMinLen, "unusable hint %d was not refused", bad)
			assert.LessOrEqual(t, n, punchFallbackMaxLen)
		}
	}
}

// The initiator's path: a bare socket, not a demux. This is the one the 97%
// measurement was taken on, and the only place the target can do its job, since
// a socket with no demux has no sampler to prefer over it.
func TestPunchPacketTakesThePadToWireLenOnABareSocket(t *testing.T) {
	rec := &recordingPacketConn{addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}}
	key, err := newPunchKey(testPunchMetadata(), testMask)
	require.NoError(t, err)
	peer := netip.MustParseAddrPort("192.0.2.2:4433")

	const modal = 1471
	for range 64 {
		sendPunchPacket(rec, peer, key, PunchPacketHello, modal)
	}
	sent := rec.written()
	require.Len(t, sent, 64)
	for _, n := range sent {
		assert.Equal(t, modal, n, "a bare-socket punch packet ignored the length it was given")
	}

	// Without one, it is back to the band that gets caught.
	rec.reset()
	for range 64 {
		sendPunchPacket(rec, peer, key, PunchPacketHello, 0)
	}
	seen := map[int]struct{}{}
	for _, n := range rec.written() {
		assert.GreaterOrEqual(t, n, punchFallbackMinLen)
		assert.LessOrEqual(t, n, punchFallbackMaxLen)
		seen[n] = struct{}{}
	}
	assert.Greater(t, len(seen), 1, "the fallback stopped varying")
}
