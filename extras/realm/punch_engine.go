package realm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	defaultPunchTimeout  = 10 * time.Second
	defaultPunchInterval = 100 * time.Millisecond

	// Symmetric (endpoint-dependent) NAT port probing. See the package
	// documentation for the arithmetic behind these numbers.
	defaultSymmetricNATProbes      = 1024
	defaultSymmetricNATProbeRate   = 100 // packets per second
	defaultSymmetricNATProbeBudget = 20 * time.Second
	// A punch that probes needs a timeout that covers the probe budget,
	// otherwise most of the probes are never sent.
	defaultSymmetricNATPunchTimeout = defaultSymmetricNATProbeBudget
	// When both ends allocate ports per destination, neither can predict the
	// other. Keep trying just long enough for a path that needs no prediction
	// (same LAN, hairpin) to answer, then let the caller fall back.
	defaultSymmetricNATBothEndsTimeout = 2 * time.Second

	symmetricNATSequentialSpan = 64
	symmetricNATStrideProbes   = 16
	// How many consecutive repeated draws end the random probe tier. Only a
	// nearly exhausted port space produces that many in a row.
	symmetricNATProbeMissLimit = 256
	// Nothing below this is a plausible NAT mapping, and probing it looks like
	// a port scan of well-known services.
	symmetricNATMinProbePort = 1024

	// The rendezvous server chooses the addresses a peer punches at, so the
	// candidate set is attacker-controlled input. Cap it, and cap the probes
	// on top of it, to bound the punch traffic a malicious realm can aim at a
	// third party. The rate limit bounds it over time; these bound it in total.
	maxPunchPeerAddrs     = 16
	maxSymmetricNATProbes = 4096
)

// PunchSourcePolicy decides which packet sources a punch attempt accepts.
// The rendezvous server can mint valid-looking punch packets, so the source
// address is the only thing separating the intended peer from one the realm
// picked. See the package documentation for why the initiator and the
// responder default to different policies.
type PunchSourcePolicy int

const (
	// PunchSourceDefault applies the policy for the role: PunchSourceCandidates
	// for the initiator, PunchSourceAny for the responder.
	PunchSourceDefault PunchSourcePolicy = iota
	// PunchSourceCandidates accepts only addresses in the candidate set, which
	// includes the ports probed on a symmetric NAT peer.
	PunchSourceCandidates
	// PunchSourceCandidateHosts accepts any port on a candidate host, for peers
	// behind a symmetric NAT whose ports cannot be predicted.
	PunchSourceCandidateHosts
	// PunchSourceAny accepts every source that decodes with the attempt's
	// metadata.
	PunchSourceAny
)

var (
	ErrInvalidPunchConfig = errors.New("invalid punch config")
	ErrPunchTimeout       = errors.New("punch timed out")
	// ErrSymmetricNATBothEnds reports the one NAT combination hole punching
	// cannot solve. Callers should read it as "stop punching, use a relay"
	// rather than as a transient failure.
	ErrSymmetricNATBothEnds = errors.New("both ends are behind endpoint-dependent NATs")
)

// SymmetricNATConfig tunes port probing against a peer whose NAT allocates a
// fresh external port per destination.
type SymmetricNATConfig struct {
	// Disable turns probing off. The announced candidates are still punched.
	Disable bool
	// LocalNAT and PeerNAT override what the address lists imply. The zero
	// value infers the class with ClassifyNAT.
	LocalNAT NATClass
	PeerNAT  NATClass
	// Probes is how many ports to guess in total, across all peer hosts.
	// Defaults to 1024.
	Probes int
	// ProbeRate caps the probes sent per second. Defaults to 100.
	ProbeRate int
	// ProbeBudget caps how long probing runs. Defaults to 20s.
	ProbeBudget time.Duration
	// BothEndsTimeout caps the whole attempt when both ends are
	// endpoint-dependent. Defaults to 2s.
	BothEndsTimeout time.Duration
}

type PunchConfig struct {
	Timeout      time.Duration
	Interval     time.Duration
	Family       AddrFamily
	SourcePolicy PunchSourcePolicy
	SymmetricNAT SymmetricNATConfig
}

type PunchResult struct {
	PeerAddr netip.AddrPort
	Packet   PunchPacket
}

// Punch performs UDP hole punching towards peerAddrs.
//
// When conn is a *PunchPacketConn, punching shares the socket with whatever
// else is on it: the demux hands punch packets to this attempt and everything
// else to the reader above, so an attempt can start at any time, including
// while QUIC is running. That is the supported way to punch, and Puncher is the
// API for it — it names the attempt, so several can run at once.
//
// Any other PacketConn is read exclusively until Punch returns, which limits it
// to bootstrapping a socket that has not been handed to QUIC yet. Once the
// connection is up, only the demux path can punch again.
//
// The returned peer address is always one the caller asked for: sources outside
// the candidate set are ignored rather than reported, so a rendezvous server
// cannot answer with metadata of its own and hand the caller a QUIC peer it
// never announced.
func Punch(ctx context.Context, conn net.PacketConn, mask PunchMask, localAddrs, peerAddrs []netip.AddrPort, meta PunchMetadata, config PunchConfig) (PunchResult, error) {
	if conn == nil {
		return PunchResult{}, fmt.Errorf("%w: conn is nil", ErrInvalidPunchConfig)
	}
	if demux, ok := conn.(*PunchPacketConn); ok {
		// The demux unmasks with the key it was built with, so an attempt that
		// masked with a different one would send packets its own conn drops.
		if !demux.mask.equal(mask) {
			return PunchResult{}, fmt.Errorf("%w: mask does not match the conn", ErrInvalidPunchConfig)
		}
		puncher, err := NewPuncher(demux)
		if err != nil {
			return PunchResult{}, err
		}
		id, err := randomAttemptID()
		if err != nil {
			return PunchResult{}, err
		}
		return puncher.Punch(ctx, id, localAddrs, peerAddrs, meta, config)
	}
	plan, err := newPunchPlan(localAddrs, peerAddrs, meta, mask, config, PunchSourceCandidates, conn.LocalAddr())
	if err != nil {
		return PunchResult{}, err
	}
	transport := &directPunchTransport{conn: conn, key: plan.key}
	defer conn.SetReadDeadline(time.Time{})
	return runPunch(ctx, transport, plan)
}

// punchTransport is how the punch loop talks to a socket. The two
// implementations differ only in where inbound punch packets come from: the
// shared demux (permanent, coexists with QUIC) or an exclusive read loop.
type punchTransport interface {
	send(to netip.AddrPort, packetType PunchPacketType, key punchKey)
	// recvUntil returns the next punch packet for this attempt, or ok=false
	// when the deadline passes first.
	recvUntil(ctx context.Context, deadline time.Time, key punchKey) (PunchPacketEvent, bool, error)
}

// punchPlan is a fully resolved punch attempt: who to send to, how fast, and
// for how long.
type punchPlan struct {
	key     punchKey
	sources punchSourceFilter

	// targets are the announced candidates. They are re-sent every interval,
	// both to punch and to keep the mapping they opened alive.
	targets  []netip.AddrPort
	interval time.Duration

	// probes are guessed ports on an endpoint-dependent peer. Each is sent
	// once, in bursts of probeBurst every probeGap, until probeBudget expires.
	probes      []netip.AddrPort
	probeBurst  int
	probeGap    time.Duration
	probeBudget time.Duration

	timeout time.Duration
	// bothEndsSymmetric records that the attempt is expected to fail, so the
	// caller can tell "no answer yet" from "no answer is possible".
	bothEndsSymmetric bool
}

func newPunchPlan(localAddrs, peerAddrs []netip.AddrPort, meta PunchMetadata, mask PunchMask, config PunchConfig, fallbackPolicy PunchSourcePolicy, local net.Addr) (punchPlan, error) {
	key, err := newPunchKey(meta, mask)
	if err != nil {
		return punchPlan{}, err
	}
	policy, err := resolvePunchSourcePolicy(config.SourcePolicy, fallbackPolicy)
	if err != nil {
		return punchPlan{}, err
	}
	targets := candidatePunchAddrs(localAddrs, peerAddrs, effectiveFamily(config.Family, local))
	if len(targets) == 0 {
		return punchPlan{}, fmt.Errorf("%w: no compatible peer addresses", ErrInvalidPunchConfig)
	}
	interval := config.Interval
	if interval == 0 {
		interval = defaultPunchInterval
	}
	if interval <= 0 {
		return punchPlan{}, fmt.Errorf("%w: interval must be positive", ErrInvalidPunchConfig)
	}

	sym := config.SymmetricNAT
	localNAT := sym.LocalNAT
	if localNAT == NATClassUnknown {
		localNAT = ClassifyNAT(localAddrs)
	}
	peerNAT := sym.PeerNAT
	if peerNAT == NATClassUnknown {
		peerNAT = ClassifyNAT(peerAddrs)
	}
	plan := punchPlan{
		key:               key,
		targets:           targets,
		interval:          interval,
		bothEndsSymmetric: localNAT == NATClassEndpointDependent && peerNAT == NATClassEndpointDependent,
	}
	// Probing is worth its packets only when we can be found at a predictable
	// port ourselves; if both ends allocate per destination, no amount of
	// guessing helps (see the package documentation).
	if !sym.Disable && peerNAT == NATClassEndpointDependent && !plan.bothEndsSymmetric {
		probes := sym.Probes
		if probes == 0 {
			probes = defaultSymmetricNATProbes
		}
		if probes < 0 {
			return punchPlan{}, fmt.Errorf("%w: probes must not be negative", ErrInvalidPunchConfig)
		}
		probes = min(probes, maxSymmetricNATProbes)
		rate := sym.ProbeRate
		if rate == 0 {
			rate = defaultSymmetricNATProbeRate
		}
		if rate < 0 {
			return punchPlan{}, fmt.Errorf("%w: probe rate must not be negative", ErrInvalidPunchConfig)
		}
		plan.probes = symmetricNATProbes(targets, probes, sym.PeerNAT == NATClassEndpointDependent)
		plan.probeBurst, plan.probeGap = probePacing(rate)
		if plan.probeBurst == 0 {
			// No rate means no probing; sending them unpaced is not an option.
			plan.probes = nil
		}
		plan.probeBudget = sym.ProbeBudget
		if plan.probeBudget == 0 {
			plan.probeBudget = defaultSymmetricNATProbeBudget
		}
		if plan.probeBudget < 0 {
			return punchPlan{}, fmt.Errorf("%w: probe budget must not be negative", ErrInvalidPunchConfig)
		}
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultPunchTimeout
		if len(plan.probes) > 0 {
			timeout = defaultSymmetricNATPunchTimeout
		}
	}
	if timeout < 0 {
		return punchPlan{}, fmt.Errorf("%w: timeout must not be negative", ErrInvalidPunchConfig)
	}
	if plan.bothEndsSymmetric {
		bothEnds := sym.BothEndsTimeout
		if bothEnds == 0 {
			bothEnds = defaultSymmetricNATBothEndsTimeout
		}
		if bothEnds < 0 {
			return punchPlan{}, fmt.Errorf("%w: both-ends timeout must not be negative", ErrInvalidPunchConfig)
		}
		timeout = min(timeout, bothEnds)
	}
	plan.timeout = timeout

	// Everything we send to is a source we expect an answer from, probes
	// included: the peer's reply leaves through the very mapping we guessed.
	plan.sources = newPunchSourceFilter(append(slices.Clip(plan.targets), plan.probes...), policy)
	return plan, nil
}

// probePacing splits a per-second rate into a burst size and the gap between
// bursts, so the loop wakes a few times per second instead of once per probe.
func probePacing(rate int) (burst int, gap time.Duration) {
	if rate <= 0 {
		return 0, 0
	}
	burst = max(1, rate/10)
	return burst, time.Second * time.Duration(burst) / time.Duration(rate)
}

func runPunch(ctx context.Context, transport punchTransport, plan punchPlan) (PunchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, plan.timeout)
	defer cancel()

	now := time.Now()
	nextTargets := now
	nextProbe := now
	probeDeadline := now.Add(plan.probeBudget)
	// The attempt ends on our own clock rather than on ctx.Err(): the context
	// reports its deadline a moment after it passes, and until it does, a loop
	// waking on that same instant would spin.
	punchDeadline := now.Add(plan.timeout)
	probeIndex := 0
	for {
		if err := ctx.Err(); err != nil {
			return PunchResult{}, plan.timeoutError(err)
		}
		now = time.Now()
		if !now.Before(punchDeadline) {
			return PunchResult{}, plan.timeoutError(context.DeadlineExceeded)
		}
		if !now.Before(nextTargets) {
			for _, target := range plan.targets {
				transport.send(target, PunchPacketHello, plan.key)
			}
			nextTargets = now.Add(plan.interval)
		}
		probing := probeIndex < len(plan.probes) && now.Before(probeDeadline)
		if probing && !now.Before(nextProbe) {
			end := min(probeIndex+plan.probeBurst, len(plan.probes))
			for _, probe := range plan.probes[probeIndex:end] {
				transport.send(probe, PunchPacketHello, plan.key)
			}
			probeIndex = end
			probing = probeIndex < len(plan.probes)
			nextProbe = now.Add(plan.probeGap)
		}

		// Wake for the next send that is actually due. Waking on a probe that
		// the budget already ruled out would spin the loop.
		deadline := punchDeadline
		if nextTargets.Before(deadline) {
			deadline = nextTargets
		}
		if probing && nextProbe.Before(deadline) {
			deadline = nextProbe
		}
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if !deadline.After(now) {
			// A deadline that has already passed belongs to a clock we do not
			// own. Wait a little rather than busy-looping until it catches up.
			deadline = now.Add(time.Millisecond)
		}
		ev, ok, err := transport.recvUntil(ctx, deadline, plan.key)
		if err != nil {
			return PunchResult{}, err
		}
		if !ok {
			continue
		}
		// Drop unexpected sources without answering: an ack would confirm to
		// whoever sent it that the metadata was right.
		if !plan.sources.allows(ev.From) {
			continue
		}
		if ev.Packet.Type == PunchPacketHello {
			transport.send(ev.From, PunchPacketAck, plan.key)
		}
		return PunchResult{
			PeerAddr: ev.From,
			Packet:   ev.Packet,
		}, nil
	}
}

func (p punchPlan) timeoutError(err error) error {
	if !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if p.bothEndsSymmetric {
		return fmt.Errorf("%w: %w", ErrPunchTimeout, ErrSymmetricNATBothEnds)
	}
	return ErrPunchTimeout
}

// directPunchTransport reads the socket itself. It cannot coexist with another
// reader, so it is only for a socket that has not been handed to QUIC yet.
type directPunchTransport struct {
	conn net.PacketConn
	key  punchKey
	buf  []byte
}

func (t *directPunchTransport) send(to netip.AddrPort, packetType PunchPacketType, key punchKey) {
	sendPunchPacket(t.conn, to, key, packetType)
}

func (t *directPunchTransport) recvUntil(ctx context.Context, deadline time.Time, key punchKey) (PunchPacketEvent, bool, error) {
	if t.buf == nil {
		t.buf = make([]byte, punchMaxWireLen)
	}
	_ = t.conn.SetReadDeadline(deadline)
	for {
		n, addr, err := t.conn.ReadFrom(t.buf)
		if err != nil {
			if isTimeout(err) {
				return PunchPacketEvent{}, false, nil
			}
			return PunchPacketEvent{}, false, err
		}
		from, ok := addrToAddrPort(addr)
		if !ok {
			continue
		}
		packet, err := decodePunchPacket(t.buf[:n], key)
		if err != nil {
			continue
		}
		return PunchPacketEvent{From: from, Packet: packet}, true, nil
	}
}

func resolvePunchSourcePolicy(policy, fallback PunchSourcePolicy) (PunchSourcePolicy, error) {
	switch policy {
	case PunchSourceDefault:
		return fallback, nil
	case PunchSourceCandidates, PunchSourceCandidateHosts, PunchSourceAny:
		return policy, nil
	default:
		return 0, fmt.Errorf("%w: unknown source policy", ErrInvalidPunchConfig)
	}
}

type punchSourceFilter struct {
	policy PunchSourcePolicy
	addrs  map[netip.AddrPort]struct{}
	hosts  map[netip.Addr]struct{}
}

func newPunchSourceFilter(candidates []netip.AddrPort, policy PunchSourcePolicy) punchSourceFilter {
	filter := punchSourceFilter{policy: policy}
	switch policy {
	case PunchSourceCandidates:
		filter.addrs = make(map[netip.AddrPort]struct{}, len(candidates))
		for _, addr := range candidates {
			filter.addrs[addr] = struct{}{}
		}
	case PunchSourceCandidateHosts:
		filter.hosts = make(map[netip.Addr]struct{}, len(candidates))
		for _, addr := range candidates {
			filter.hosts[addr.Addr()] = struct{}{}
		}
	}
	return filter
}

func (f punchSourceFilter) allows(addr netip.AddrPort) bool {
	switch f.policy {
	case PunchSourceCandidates:
		_, ok := f.addrs[addr]
		return ok
	case PunchSourceCandidateHosts:
		_, ok := f.hosts[addr.Addr()]
		return ok
	case PunchSourceAny:
		return true
	default:
		return false
	}
}

// sendPunchPacket puts one punch packet on the wire at a length the socket has
// already sent, when it is a conn that can tell us one.
func sendPunchPacket(conn net.PacketConn, addr netip.AddrPort, key punchKey, packetType PunchPacketType) {
	demux, _ := conn.(*PunchPacketConn)
	var (
		wireLen int
		err     error
	)
	if demux != nil {
		wireLen, err = demux.sampleWireLen()
	} else {
		wireLen, err = fallbackPunchWireLen()
	}
	if err != nil {
		return
	}
	packet, err := encodePunchPacket(packetType, key, wireLen)
	if err != nil {
		return
	}
	if demux != nil {
		// Not through WriteTo: a punch packet must not become a sample.
		_, _ = demux.writePunch(packet, udpAddrFromAddrPort(addr))
		return
	}
	_, _ = conn.WriteTo(packet, udpAddrFromAddrPort(addr))
}

func candidatePunchAddrs(localAddrs, peerAddrs []netip.AddrPort, family AddrFamily) []netip.AddrPort {
	allowedFamilies := punchFamilies(localAddrs, family)
	allowLoopback := containsLoopback(localAddrs)
	seen := make(map[netip.AddrPort]struct{})
	var candidates []netip.AddrPort
	for _, addr := range peerAddrs {
		if len(candidates) >= maxPunchPeerAddrs {
			break
		}
		// Received addresses are unmapped (see addrToAddrPort), so candidates
		// must be too, or a peer announced in v4-in-v6 form would be punched
		// but never accepted.
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		if !punchableTarget(addr, allowLoopback) {
			continue
		}
		if !allowedFamilies.allows(addr.Addr()) {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		candidates = append(candidates, addr)
	}
	sortAddrPorts(candidates)
	return candidates
}

// punchableTarget rejects addresses that are meaningless or dangerous as punch
// targets. Peer addresses come from the rendezvous server, which must not be
// able to make a client spray packets at its own services or at a broadcast
// group.
func punchableTarget(addr netip.AddrPort, allowLoopback bool) bool {
	if !addr.IsValid() || addr.Port() == 0 {
		return false
	}
	ip := addr.Addr()
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	// Loopback is only a real peer address when we are one ourselves, which in
	// practice means tests: STUN never reflects a loopback address.
	return !ip.IsLoopback() || allowLoopback
}

func containsLoopback(addrs []netip.AddrPort) bool {
	for _, addr := range addrs {
		if addr.IsValid() && addr.Addr().IsLoopback() {
			return true
		}
	}
	return false
}

func sortAddrPorts(addrs []netip.AddrPort) {
	slices.SortFunc(addrs, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})
}

type punchFamilySet struct {
	v4 bool
	v6 bool
}

func punchFamilies(localAddrs []netip.AddrPort, family AddrFamily) punchFamilySet {
	switch family {
	case AddrFamilyIPv4:
		return punchFamilySet{v4: true}
	case AddrFamilyIPv6:
		return punchFamilySet{v6: true}
	}
	// Otherwise derive the families from the locally gathered addresses,
	// falling back to both when none are known.
	var families punchFamilySet
	for _, addr := range localAddrs {
		if !addr.IsValid() {
			continue
		}
		if addr.Addr().Is4() {
			families.v4 = true
		} else if addr.Addr().Is6() {
			families.v6 = true
		}
	}
	if !families.v4 && !families.v6 {
		families.v4 = true
		families.v6 = true
	}
	return families
}

func (s punchFamilySet) allows(addr netip.Addr) bool {
	if addr.Is4() {
		return s.v4
	}
	if addr.Is6() {
		return s.v6
	}
	return false
}

func addrToAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ipAddr, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok || udpAddr.Port <= 0 || udpAddr.Port > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ipAddr.Unmap(), uint16(udpAddr.Port)), true
}

func udpAddrFromAddrPort(addr netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP(addr.Addr().AsSlice()),
		Port: int(addr.Port()),
	}
}
