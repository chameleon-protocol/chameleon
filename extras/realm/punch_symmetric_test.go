package realm

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testLocalUDPAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 1234}

func TestPunchProbesEndpointDependentPeer(t *testing.T) {
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:51234"),
	}
	plan, err := newPunchPlan([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")},
		peer, testPunchMetadata(), PunchConfig{}, PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)

	assert.Len(t, plan.probes, defaultSymmetricNATProbes)
	// A reply comes back through the very mapping we guessed, so a probed port
	// has to be an accepted source or the answer would be dropped.
	for _, probe := range plan.probes[:8] {
		assert.True(t, plan.sources.allows(probe), "probe %v is not an accepted source", probe)
	}
	// Probing needs a timeout that covers its budget.
	assert.GreaterOrEqual(t, plan.timeout, plan.probeBudget)
}

func TestPunchDoesNotProbeAPredictablePeer(t *testing.T) {
	peer := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:40000")}
	plan, err := newPunchPlan([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")},
		peer, testPunchMetadata(), PunchConfig{}, PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)

	assert.Empty(t, plan.probes)
	assert.Equal(t, defaultPunchTimeout, plan.timeout)
}

func TestPunchProbingCanBeDisabled(t *testing.T) {
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:51234"),
	}
	plan, err := newPunchPlan([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")},
		peer, testPunchMetadata(), PunchConfig{SymmetricNAT: SymmetricNATConfig{Disable: true}},
		PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)
	assert.Empty(t, plan.probes)
}

// Probing is a packet flood by construction, aimed at addresses the rendezvous
// server chose. The rate cap is what keeps it from being one.
func TestPunchProbesStayUnderTheRateLimit(t *testing.T) {
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:51234"),
	}
	const rate = 100
	const timeout = 350 * time.Millisecond
	plan, err := newPunchPlan([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")},
		peer, testPunchMetadata(), PunchConfig{
			Timeout: timeout,
			// Long enough that the announced candidates are sent once and do
			// not muddy the count.
			Interval:     time.Hour,
			SymmetricNAT: SymmetricNATConfig{ProbeRate: rate},
		}, PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)

	transport := &recordingPunchTransport{}
	start := time.Now()
	_, err = runPunch(context.Background(), transport, plan)
	elapsed := time.Since(start)
	assert.ErrorIs(t, err, ErrPunchTimeout)

	announced := make(map[netip.AddrPort]struct{}, len(plan.targets))
	for _, target := range plan.targets {
		announced[target] = struct{}{}
	}
	probes := 0
	for _, sent := range transport.sent() {
		if _, ok := announced[sent]; !ok {
			probes++
		}
	}
	burst, _ := probePacing(rate)
	limit := int(elapsed.Seconds()*rate) + burst
	assert.LessOrEqual(t, probes, limit, "sent %d probes in %v", probes, elapsed)
	assert.GreaterOrEqual(t, probes, burst, "probing never started")
}

func TestPunchStopsProbingAfterTheBudget(t *testing.T) {
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:51234"),
	}
	plan, err := newPunchPlan([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")},
		peer, testPunchMetadata(), PunchConfig{
			Timeout:  400 * time.Millisecond,
			Interval: time.Hour,
			SymmetricNAT: SymmetricNATConfig{
				ProbeRate:   100,
				ProbeBudget: 100 * time.Millisecond,
			},
		}, PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)

	transport := &recordingPunchTransport{}
	_, err = runPunch(context.Background(), transport, plan)
	assert.ErrorIs(t, err, ErrPunchTimeout)

	announced := make(map[netip.AddrPort]struct{}, len(plan.targets))
	for _, target := range plan.targets {
		announced[target] = struct{}{}
	}
	probes := 0
	for _, sent := range transport.sent() {
		if _, ok := announced[sent]; !ok {
			probes++
		}
	}
	burst, _ := probePacing(100)
	// One burst at the start of the budget, at most one more at its end.
	assert.LessOrEqual(t, probes, 2*burst)
	// And once the budget is spent the loop waits for the timeout instead of
	// spinning on a probe deadline that has already passed.
	assert.LessOrEqual(t, transport.waitCount(), 20)
}

// Neither side can predict the other's port, so probing would burn its whole
// budget for nothing. Fail fast instead and let the caller fall back.
func TestPunchGivesUpFastWhenBothEndsAreEndpointDependent(t *testing.T) {
	local := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:1234"),
		netip.MustParseAddrPort("192.0.2.10:5678"),
	}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:51234"),
	}
	plan, err := newPunchPlan(local, peer, testPunchMetadata(), PunchConfig{
		Timeout:      time.Hour,
		Interval:     10 * time.Millisecond,
		SymmetricNAT: SymmetricNATConfig{BothEndsTimeout: 100 * time.Millisecond},
	}, PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)
	assert.Empty(t, plan.probes, "probing an unpredictable peer from an unpredictable port is hopeless")
	assert.Equal(t, 100*time.Millisecond, plan.timeout)

	transport := &recordingPunchTransport{}
	start := time.Now()
	_, err = runPunch(context.Background(), transport, plan)
	elapsed := time.Since(start)

	assert.ErrorIs(t, err, ErrPunchTimeout)
	assert.ErrorIs(t, err, ErrSymmetricNATBothEnds)
	assert.Less(t, elapsed, time.Second)
	// The announced candidates are still tried: a LAN or hairpin path needs no
	// prediction at all.
	assert.NotEmpty(t, transport.sent())
}

func TestPunchBothEndsEndpointDependentEndToEnd(t *testing.T) {
	meta := testPunchMetadata()
	client := listenUDP4(t)
	defer client.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	clientAddr := packetConnAddrPort(t, client)
	peerAddr := packetConnAddrPort(t, peer)
	local := []netip.AddrPort{clientAddr, netip.AddrPortFrom(clientAddr.Addr(), clientAddr.Port()+1000)}
	// The peer never answers, so this is the give-up path end to end.
	peers := []netip.AddrPort{peerAddr, netip.AddrPortFrom(peerAddr.Addr(), peerAddr.Port()+1000)}

	start := time.Now()
	_, err := Punch(context.Background(), client, local, peers, meta, PunchConfig{
		Timeout:      time.Hour,
		Interval:     10 * time.Millisecond,
		SymmetricNAT: SymmetricNATConfig{BothEndsTimeout: 100 * time.Millisecond},
	})
	assert.ErrorIs(t, err, ErrSymmetricNATBothEnds)
	assert.Less(t, time.Since(start), time.Second)
}

func TestPunchNATClassOverridesWinOverInference(t *testing.T) {
	// One announced port per host says nothing, but the caller may know better
	// (a peer that reported its own NAT class, say).
	peer := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:40000")}
	plan, err := newPunchPlan([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")},
		peer, testPunchMetadata(), PunchConfig{
			SymmetricNAT: SymmetricNATConfig{PeerNAT: NATClassEndpointDependent, Probes: 32},
		}, PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)
	assert.Len(t, plan.probes, 32)

	// And a caller that knows it is behind an endpoint-dependent NAT itself
	// gets the fast give-up even though its own address list is inconclusive.
	plan, err = newPunchPlan([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")},
		peer, testPunchMetadata(), PunchConfig{
			SymmetricNAT: SymmetricNATConfig{
				LocalNAT: NATClassEndpointDependent,
				PeerNAT:  NATClassEndpointDependent,
			},
		}, PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)
	assert.Empty(t, plan.probes)
	assert.Equal(t, defaultSymmetricNATBothEndsTimeout, plan.timeout)
}

func TestPunchProbeCountIsCapped(t *testing.T) {
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:51234"),
	}
	plan, err := newPunchPlan([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")},
		peer, testPunchMetadata(), PunchConfig{
			SymmetricNAT: SymmetricNATConfig{Probes: 1 << 20},
		}, PunchSourceCandidates, testLocalUDPAddr)
	require.NoError(t, err)
	assert.Len(t, plan.probes, maxSymmetricNATProbes)
}

// recordingPunchTransport records what a punch sends and never answers.
type recordingPunchTransport struct {
	mu     sync.Mutex
	sentTo []netip.AddrPort
	waits  int
}

func (t *recordingPunchTransport) send(to netip.AddrPort, _ PunchPacketType, _ punchKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sentTo = append(t.sentTo, to)
}

func (t *recordingPunchTransport) recvUntil(ctx context.Context, deadline time.Time, _ punchKey) (PunchPacketEvent, bool, error) {
	t.mu.Lock()
	t.waits++
	t.mu.Unlock()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	return PunchPacketEvent{}, false, nil
}

func (t *recordingPunchTransport) waitCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.waits
}

func (t *recordingPunchTransport) sent() []netip.AddrPort {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netip.AddrPort(nil), t.sentTo...)
}
