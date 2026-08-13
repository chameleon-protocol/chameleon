package netem

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func candidate(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

func key(t *testing.T, a net.Addr) netip.AddrPort {
	t.Helper()
	k, ok := PeerKey(a)
	require.True(t, ok, "%v should be usable as a candidate key", a)
	return k
}

func TestPeerKeyUnmapsIPv4(t *testing.T) {
	// A dual-stack socket reports ::ffff:127.0.0.1 for a peer the test spelled
	// 127.0.0.1. If those two produced different keys, a rule set from the test's
	// spelling would silently never match the traffic.
	four := key(t, candidate(9000))
	mapped, err := netip.ParseAddrPort("[::ffff:127.0.0.1]:9000")
	require.NoError(t, err)
	assert.Equal(t, four, netip.AddrPortFrom(mapped.Addr().Unmap(), mapped.Port()))

	_, ok := PeerKey(nil)
	assert.False(t, ok)
	_, ok = PeerKey(&net.UnixAddr{Name: "/tmp/x", Net: "unixgram"})
	assert.False(t, ok, "an address with no port cannot name a candidate")
}

func TestSetForImpairsOneCandidateOnly(t *testing.T) {
	f := newFakeConn()
	ctrl := NewController(Clean())
	c := ctrl.Wrap(f)
	defer c.Close()

	dead, alive, unnamed := candidate(1), candidate(2), candidate(3)
	ctrl.SetFor(key(t, dead), Blocked())
	ctrl.SetFor(key(t, alive), Clean())

	const n = 20
	for i := 0; i < n; i++ {
		for _, to := range []*net.UDPAddr{dead, alive, unnamed} {
			_, err := c.WriteTo(seqPacket(i), to)
			require.NoError(t, err)
		}
	}

	assert.Equal(t, 0, f.sentTo(dead), "the blackholed candidate must put nothing on the wire")
	assert.Equal(t, n, f.sentTo(alive))
	assert.Equal(t, n, f.sentTo(unnamed), "a candidate no rule names keeps the default profile")

	assert.Equal(t, uint64(n), ctrl.StatsFor(key(t, dead)).Up.Dropped)
	assert.Equal(t, uint64(0), ctrl.StatsFor(key(t, dead)).Up.Out)
	assert.Equal(t, uint64(n), ctrl.StatsFor(key(t, alive)).Up.Out)
	assert.Equal(t, Stats{}, ctrl.StatsFor(key(t, unnamed)),
		"only a candidate SetFor named gets counters of its own")

	// The grand total still covers everything, named or not: 3n offered up, n of
	// them dropped.
	total := ctrl.Stats()
	assert.Equal(t, uint64(3*n), total.Up.In)
	assert.Equal(t, uint64(n), total.Up.Dropped)
}

func TestSetForSplitsTheReceiveDirection(t *testing.T) {
	f := newFakeConn()
	ctrl := NewController(Clean())
	c := ctrl.Wrap(f)
	defer c.Close()

	dead, alive := candidate(1), candidate(2)
	ctrl.SetFor(key(t, dead), Blocked())
	ctrl.SetFor(key(t, alive), Clean())

	const n = 10
	for i := 0; i < n; i++ {
		f.deliverFrom(dead, seqPacket(i))
		f.deliverFrom(alive, seqPacket(i))
	}

	buf := make([]byte, 128)
	for i := 0; i < n; i++ {
		require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
		_, from, err := c.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, alive.String(), from.String(),
			"nothing from the blackholed candidate may reach the application")
	}
	require.NoError(t, c.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err := c.ReadFrom(buf)
	assert.Error(t, err)

	assert.Equal(t, uint64(n), ctrl.StatsFor(key(t, dead)).Down.Dropped)
	assert.Equal(t, uint64(n), ctrl.StatsFor(key(t, alive)).Down.Out)
}

func TestSetForTakesEffectOnALiveConn(t *testing.T) {
	// The whole point is to cut a candidate while traffic is running, so the rule
	// has to reach a Conn that already exists -- and, once the candidate already
	// has pipes of its own, a later change has to reach those too.
	f := newFakeConn()
	ctrl := NewController(Clean())
	c := ctrl.Wrap(f)
	defer c.Close()

	to := candidate(1)
	ctrl.SetFor(key(t, to), Clean())
	_, err := c.WriteTo(seqPacket(0), to)
	require.NoError(t, err)
	require.Equal(t, 1, f.sentTo(to))

	ctrl.SetFor(key(t, to), Blocked())
	_, err = c.WriteTo(seqPacket(1), to)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sentTo(to), "the cut must land on the datagram after it")

	ctrl.ClearFor(key(t, to))
	_, err = c.WriteTo(seqPacket(2), to)
	require.NoError(t, err)
	assert.Equal(t, 2, f.sentTo(to), "ClearFor puts the candidate back on the default")

	// ClearFor reverts the impairment but not the split: the counters carry on.
	assert.Equal(t, uint64(3), ctrl.StatsFor(key(t, to)).Up.In)
}

func TestSetForKeepsCandidateQueuesApart(t *testing.T) {
	// Two candidates behind one queue would make a datagram held on the slow one
	// delay a datagram on the fast one, which is the opposite of what separate
	// paths mean. This is the assertion that keeps the pipes separate.
	f := newFakeConn()
	ctrl := NewController(Clean())
	c := ctrl.Wrap(f)
	defer c.Close()

	slow, fast := candidate(1), candidate(2)
	ctrl.SetFor(key(t, slow), RTT(400*time.Millisecond))
	ctrl.SetFor(key(t, fast), Clean())

	_, err := c.WriteTo(seqPacket(0), slow)
	require.NoError(t, err)
	_, err = c.WriteTo(seqPacket(1), fast)
	require.NoError(t, err)

	require.Equal(t, 1, f.sentTo(fast), "the fast candidate must not wait behind the slow one")
	assert.Equal(t, 0, f.sentTo(slow))
	assert.True(t, waitFor(t, 2*time.Second, func() bool { return f.sentTo(slow) == 1 }))
}

func TestStatsForSurvivesConnClose(t *testing.T) {
	// A failover test reconnects, which throws the socket away. If the per-
	// candidate counters went with it, "the traffic moved to candidate 1" would
	// be unprovable across exactly the event it is about.
	f := newFakeConn()
	ctrl := NewController(Clean())
	c := ctrl.Wrap(f)

	to := candidate(1)
	ctrl.SetFor(key(t, to), Clean())
	for i := 0; i < 5; i++ {
		_, err := c.WriteTo(seqPacket(i), to)
		require.NoError(t, err)
	}
	require.NoError(t, c.Close())

	assert.Equal(t, uint64(5), ctrl.StatsFor(key(t, to)).Up.Out)
}
