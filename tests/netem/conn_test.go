package netem

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitFor polls until cond holds or the deadline passes. Impaired links release
// packets from a scheduler goroutine, so the tests below assert on outcomes
// rather than on when a particular goroutine happened to run.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

func seqPacket(i int) []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint32(b, uint32(i))
	return b
}

func seqOf(b []byte) int { return int(binary.BigEndian.Uint32(b)) }

func TestCleanLinkForwardsEverything(t *testing.T) {
	f := newFakeConn()
	c := Wrap(f, Clean())
	defer c.Close()

	const n = 100
	for i := 0; i < n; i++ {
		written, err := c.WriteTo(seqPacket(i), f.addr)
		require.NoError(t, err)
		assert.Equal(t, 64, written)
	}
	require.Equal(t, n, f.sentCount(), "a clean link must not drop or defer")
	for i, s := range f.sent() {
		assert.Equal(t, i, seqOf(s.data))
	}

	for i := 0; i < n; i++ {
		f.deliver(seqPacket(i))
	}
	buf := make([]byte, 128)
	for i := 0; i < n; i++ {
		require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
		read, addr, err := c.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, 64, read)
		assert.Equal(t, f.addr, addr)
		assert.Equal(t, i, seqOf(buf[:read]))
	}

	st := c.Stats()
	assert.Zero(t, st.Up.Dropped)
	assert.Zero(t, st.Down.Dropped)
	assert.Zero(t, st.Overflow)
	assert.EqualValues(t, n, st.Up.Out)
	assert.EqualValues(t, n, st.Down.Out)
}

func TestLossRateMatchesConfiguration(t *testing.T) {
	const n = 4000
	for _, rate := range []float64{0, 0.01, 0.05, 0.5} {
		t.Run(Loss(rate).Name, func(t *testing.T) {
			f := newFakeConn()
			c := Wrap(f, Loss(rate))
			defer c.Close()

			for i := 0; i < n; i++ {
				_, err := c.WriteTo(seqPacket(i), f.addr)
				require.NoError(t, err, "a dropped packet must still look like a successful send")
			}
			got := c.Stats().Up
			assert.EqualValues(t, n, got.In)
			assert.EqualValues(t, n, got.Out+got.Dropped)
			assert.EqualValues(t, got.Out, f.sentCount())
			// 4000 draws puts the sample loss rate within ~1.5 points of the
			// configured one with room to spare, even at p=0.5.
			assert.InDelta(t, rate, got.LossRate(), 0.02)
		})
	}
}

func TestBlackholeDropsEverythingButStillAcceptsWrites(t *testing.T) {
	f := newFakeConn()
	c := Wrap(f, Blocked())
	defer c.Close()

	for i := 0; i < 50; i++ {
		written, err := c.WriteTo(seqPacket(i), f.addr)
		require.NoError(t, err)
		assert.Equal(t, 64, written)
		f.deliver(seqPacket(i))
	}
	assert.Zero(t, f.sentCount())

	require.NoError(t, c.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, _, err := c.ReadFrom(make([]byte, 128))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)

	st := c.Stats()
	assert.EqualValues(t, 50, st.Up.Dropped)
	assert.EqualValues(t, 50, st.Down.Dropped)
}

func TestDelayHoldsPacketsForTheConfiguredTime(t *testing.T) {
	const delay = 60 * time.Millisecond
	f := newFakeConn()
	c := Wrap(f, Profile{Up: Link{Delay: delay}})
	defer c.Close()

	start := time.Now()
	_, err := c.WriteTo(seqPacket(0), f.addr)
	require.NoError(t, err)
	assert.Zero(t, f.sentCount(), "a delayed packet must not leave synchronously")

	require.True(t, waitFor(t, 2*time.Second, func() bool { return f.sentCount() == 1 }))
	held := f.sent()[0].at.Sub(start)
	assert.GreaterOrEqual(t, held, delay-5*time.Millisecond)
	assert.Less(t, held, delay+time.Second, "scheduler overshoot beyond a second is a bug, not load")
}

func TestDelayWithoutJitterPreservesOrder(t *testing.T) {
	const n = 300
	f := newFakeConn()
	c := Wrap(f, RTT(20*time.Millisecond))
	defer c.Close()

	for i := 0; i < n; i++ {
		_, err := c.WriteTo(seqPacket(i), f.addr)
		require.NoError(t, err)
	}
	require.True(t, waitFor(t, 5*time.Second, func() bool { return f.sentCount() == n }))
	for i, s := range f.sent() {
		require.Equal(t, i, seqOf(s.data), "a link without jitter must not reorder")
	}
}

func TestJitterReorders(t *testing.T) {
	const n = 400
	f := newFakeConn()
	c := Wrap(f, RTT(40*time.Millisecond).WithJitter(60*time.Millisecond))
	defer c.Close()

	for i := 0; i < n; i++ {
		_, err := c.WriteTo(seqPacket(i), f.addr)
		require.NoError(t, err)
	}
	require.True(t, waitFor(t, 5*time.Second, func() bool { return f.sentCount() == n }))
	out := f.sent()
	reordered := false
	for i := 1; i < len(out); i++ {
		if seqOf(out[i].data) < seqOf(out[i-1].data) {
			reordered = true
			break
		}
	}
	assert.True(t, reordered, "jitter wider than the inter-packet gap must reorder")
}

func TestRateLimitPacesTraffic(t *testing.T) {
	const (
		rate     = 1 << 20 // 1MB/s
		burst    = 16 << 10
		packet   = 4 << 10
		packets  = 32 // 128KB total
		expected = time.Duration(float64(packets*packet-burst) / rate * float64(time.Second))
	)
	f := newFakeConn()
	c := Wrap(f, Profile{Up: Link{Rate: rate, Burst: burst}})
	defer c.Close()

	start := time.Now()
	for i := 0; i < packets; i++ {
		_, err := c.WriteTo(make([]byte, packet), f.addr)
		require.NoError(t, err)
	}
	require.True(t, waitFor(t, 5*time.Second, func() bool { return f.sentCount() == packets }))
	took := f.sent()[packets-1].at.Sub(start)

	assert.GreaterOrEqual(t, took, expected*3/4, "the shaper let traffic through faster than its rate")
	assert.Less(t, took, expected*4+500*time.Millisecond)
	assert.Zero(t, c.Stats().Up.Dropped, "a backlog this small must not overflow the queue")
}

func TestRateLimitTailDropsOnQueueOverflow(t *testing.T) {
	f := newFakeConn()
	c := Wrap(f, Profile{Up: Link{Rate: 1 << 10, Burst: 1 << 10, Queue: 8}})
	defer c.Close()

	for i := 0; i < 200; i++ {
		_, err := c.WriteTo(make([]byte, 512), f.addr)
		require.NoError(t, err)
	}
	st := c.Stats().Up
	assert.Greater(t, st.Dropped, uint64(100), "a full shaper queue must tail-drop")
	assert.EqualValues(t, 200, st.In)
}

func TestReadDeadlineExpiresAndClears(t *testing.T) {
	f := newFakeConn()
	c := Wrap(f, Clean())
	defer c.Close()

	require.NoError(t, c.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	_, _, err := c.ReadFrom(make([]byte, 128))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	// quic-go interrupts its read loop with a past deadline and then clears it,
	// so clearing has to make the conn readable again.
	require.NoError(t, c.SetReadDeadline(time.Time{}))
	f.deliver(seqPacket(7))
	buf := make([]byte, 128)
	n, _, err := c.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, 7, seqOf(buf[:n]))
}

func TestReadDeadlineInterruptsBlockedRead(t *testing.T) {
	f := newFakeConn()
	c := Wrap(f, Clean())
	defer c.Close()

	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 128))
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, c.SetReadDeadline(time.Now()))
	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("setting a past deadline did not interrupt the blocked read")
	}
}

func TestCloseUnblocksReadAndRejectsWrites(t *testing.T) {
	f := newFakeConn()
	c := Wrap(f, Clean())

	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 128))
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close(), "Close must be idempotent: quic-go closes the transport and the conn")

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the pending read")
	}
	_, err := c.WriteTo(seqPacket(0), f.addr)
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestReceiveQueueOverflowIsCountedApart(t *testing.T) {
	f := newFakeConn()
	c := Wrap(f, Clean())
	defer c.Close()

	// Nobody reads, so everything past the receive queue is lost the way a
	// kernel socket loses it -- but it must not be blamed on the profile.
	for i := 0; i < defaultRecvQueue+500; i++ {
		f.deliver(seqPacket(i))
	}
	require.True(t, waitFor(t, 5*time.Second, func() bool { return c.Stats().Overflow > 0 }))
	st := c.Stats()
	assert.Zero(t, st.Down.Dropped, "a clean link drops nothing; overflow is the reader's fault")
	assert.Positive(t, st.Overflow)
}

func TestControllerRetunesLiveConn(t *testing.T) {
	f := newFakeConn()
	ctrl := NewController(Clean())
	c := ctrl.Wrap(f)
	defer c.Close()

	_, err := c.WriteTo(seqPacket(0), f.addr)
	require.NoError(t, err)
	require.Equal(t, 1, f.sentCount())

	ctrl.SetBlackhole(true)
	_, err = c.WriteTo(seqPacket(1), f.addr)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sentCount(), "blackhole must apply to sockets that already exist")

	ctrl.SetBlackhole(false)
	_, err = c.WriteTo(seqPacket(2), f.addr)
	require.NoError(t, err)
	assert.Equal(t, 2, f.sentCount(), "restoring the link must not need a new socket")
}

func TestControllerStatsSurviveConnClose(t *testing.T) {
	ctrl := NewController(Loss(1))
	f1 := newFakeConn()
	c1 := ctrl.Wrap(f1)
	for i := 0; i < 10; i++ {
		_, err := c1.WriteTo(seqPacket(i), f1.addr)
		require.NoError(t, err)
	}
	require.NoError(t, c1.Close())

	f2 := newFakeConn()
	c2 := ctrl.Wrap(f2)
	defer c2.Close()
	for i := 0; i < 5; i++ {
		_, err := c2.WriteTo(seqPacket(i), f2.addr)
		require.NoError(t, err)
	}
	assert.EqualValues(t, 15, ctrl.Stats().Up.Dropped, "reconnecting must not reset the counters")
}

func TestConnFactoryWrapsRealSockets(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer peer.Close()

	ctrl := NewController(Clean())
	pc, err := ConnFactory{ctrl}.New(peer.LocalAddr())
	require.NoError(t, err)
	defer pc.Close()

	_, err = pc.WriteTo([]byte("ping"), peer.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 64)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, from, err := peer.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))
	// The factory binds a wildcard address, so only the port is comparable.
	assert.Equal(t, pc.LocalAddr().(*net.UDPAddr).Port, from.(*net.UDPAddr).Port)

	_, err = peer.WriteTo([]byte("pong"), from)
	require.NoError(t, err)
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, err = pc.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf[:n]))
}

func TestDeadlineExceededIsATemporaryNetError(t *testing.T) {
	// quic-go's read loop only keeps going after a read error if the error is a
	// net.Error that reports itself temporary; anything else tears the
	// transport down.
	var netErr net.Error
	require.True(t, errors.As(error(os.ErrDeadlineExceeded), &netErr))
	assert.True(t, netErr.Timeout())
}
