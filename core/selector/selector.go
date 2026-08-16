// Package selector decides, from what a connection can actually observe, that
// the path it is on is not coming back and that a different candidate should be
// tried.
//
// It is the decision and not the transport. Observations go in, decisions come
// out, and nothing here dials, sends, or holds a *quic.Conn -- so the policy can
// be run over tables of synthetic readings with no network at all, which is the
// only way the thresholds below can be held to the measurements they came from.
// Carrying a decision out is core/client.PathController's job.
//
// What the decision rests on is one signal, and one only:
// how long since the transport last counted a packet received.
// Everything else on pathstats.Stats was measured and rejected --
//
//   - SmoothedRTT freezes on a dead path rather than rising, because an estimate
//     only moves when an ack arrives, so "the round trip is still small" is true
//     of a healthy path and a dead one alike.
//   - The rate of fresh RTT samples is 1/RTT, so it collapses on a slow path as
//     hard as on a dead one; the two sets overlapped, in one run at zero.
//   - MinRTT is a lifetime minimum and cannot rise, so SmoothedRTT-MinRTT stops
//     meaning "the queueing on this path" after any reroute.
//   - PacketsLost, BytesLost and LossRate are written only by quic-go's own Cubic
//     sender, and core/client replaces the congestion controller at
//     authentication in every shipped configuration, so they read zero forever.
//   - PacketsSent describes the congestion controller and the loss-recovery
//     timers, not the path: into one identical blackhole BBR put 1270 packets on
//     the wire and Brutal 258.
//
// Receive silence separates the cases that should switch from the cases that
// should not, and it is the only thing that does.
//
// Four things the policy will not do, each for a measured reason.
//
// It will not leave a path that is still producing evidence. That is not
// conservatism, it is the second measurement: switching into a candidate sitting
// behind a buffer a neighbour keeps full locks the connection's path minimum at
// 487ms against the 20ms path it left, sizes the congestion window at 2.6 MB
// where 84 kB is right, and is still wrong six seconds later. A minimum cannot
// rise, so no controller can repair it. The harm in that case is entirely in
// what was given up -- a working 20ms path -- which is why the rule that avoids
// it is "silence is the only reason to move" and not a ceiling on a candidate's
// round trip.
//
// Say the rest of that plainly, because it is a limit and not a design. Nothing
// this connection can observe about a candidate it is not using distinguishes
// the one behind that buffer from any other: a path in use is described by
// pathstats.Stats, and a path not in use is described by nothing at all. What
// would distinguish it is a round trip measured on the candidate itself --
// send something to it, time the answer, and 487ms against 20ms is not a close
// call -- and that probe does not exist yet. Until it does, a candidate is an
// address and the policy is choosing blind.
//
// Recognising it afterwards is possible and is still not worth doing.
// SmoothedRTT does climb to the new path's round trip within a few samples, so
// "the candidate I moved to is twenty times slower" is observable once the move
// has been made. Moving back is what cannot be justified: it costs a second
// round trip and a second congestion-controller reset, the round-trip state it
// would be returning to has already been overwritten, and the path it would
// return to is the one that had stopped delivering -- the policy has no evidence
// that it has come back, and getting that evidence needs the same probe. So the
// only move into a bad candidate this policy will make is a move off a path that
// had gone silent, where the comparison is 487ms against nothing.
//
// It will not switch on an idle connection, and the signal that makes idleness
// distinguishable from a blackhole is named rather than inferred: the QUIC
// keep-alive. quic-go sends a ping when nothing has been received for
// max(min(KeepAlivePeriod, idleTimeout/2), 1.5*PTO) -- connection.go's
// nextKeepAliveTime, anchored on the last packet received, not the last one sent
// -- so a connection with nothing to say still asks the far end a question at a
// known rate. Silence longer than that interval means we asked and were not
// answered. Silence shorter than it means nothing at all, on any connection.
// With KeepAlivePeriod at zero quic-go asks nothing, no amount of silence is
// evidence, and this package refuses to conclude anything from it.
//
// It will not walk the candidate list twice on one connection. Each candidate is
// tried once, and when the list runs out the answer is GiveUp until the
// connection underneath is replaced. The rule is what it is because the
// alternative was measured: a policy that let a path back onto the list after it
// had delivered a packet and then held quiet for a threshold was falsifiable by
// one packet per threshold. A link dribbling at exactly that rate drew 20
// switches in 65 seconds against the 3.05s threshold that policy had, and 14
// against this one, cycling two candidates and back either way.
//
// Nothing separates that link from a healthy idle one by counting packets: at a
// 2s keep-alive a healthy idle connection delivers one answer per 2.05s and the
// dribbling link one per threshold, and one lost keep-alive answer moves the
// healthy connection across any line drawn between them. So the ambiguity is
// resolved the cheap way: the walk is finite, and starting it again is the
// caller's decision to make by replacing the connection, which resets far more
// than a switch can.
//
// It will not be fast. A passive detector cannot beat the rate at which the
// connection gives the far end something to answer: at the shipped 30s idle
// timeout and 10s keep-alive the threshold is just over twelve seconds, against
// a stack verdict past thirty-one. Knowing sooner requires producing the
// evidence rather than waiting for it -- sending on a candidate and timing the
// answer -- and that is the same probe again.
package selector

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/chameleon-protocol/chameleon/core/v2/pathstats"
)

// The three terms of the threshold, and where each came from. One is measured,
// two are read out of quic-go, and the difference is not cosmetic: the measured
// one can be re-measured, and the derived ones change if quic-go changes.
const (
	// silenceSlack is the headroom above the keep-alive interval and the round
	// trip, and what it is sized for is a reroute the round-trip term has not
	// caught up with yet.
	//
	// Start with what it has to cover on a connection with nothing wrong.
	// MEASURED: on a 50ms link, one exchange and then silence, the longest gap
	// between packets received was 2.061s at a 2s keep-alive and 10.061s at 10s.
	// 61ms of overhead in both, of which 50ms is the round trip the answer to the
	// ping has to make and 20ms the interval the detector polled at, so what is
	// left over is about 11ms. Eleven milliseconds is not what sets this
	// constant.
	//
	// What sets it is the reroute, and the number was swept rather than reasoned
	// about. On an idle connection every packet received is an answer to a ping,
	// so the gap is the interval plus the round trip -- and when a path reroutes,
	// the round trip in that gap is the new one while the round trip in the
	// threshold is still the old one, because SmoothedRTT only moves when an
	// answer arrives and the answer is what is late. The whole of the reroute
	// therefore has to fit in this constant. Sweeping the rerouted round trip in
	// 50ms steps on the 2s keep-alive bed, with SmoothedRTT held at the 50ms the
	// path had before: at 1.05s the policy stays, and at 1.1s and above it
	// switches away from a path that is answering every single ping. That was
	// with this constant at 1s.
	//
	// It is 2s, which puts the bound at a reroute to a 2.05s round trip, twice
	// the largest step the sweep measured (50ms to 1s, rtt-step-1s). Say
	// the residual out loud rather than leaving it to be found: a reroute past
	// that on an idle connection still condemns a working path, and no passive reading
	// of this connection can do better, because the evidence that would exculpate
	// the path is exactly the evidence being withheld.
	//
	// The cost is a slower detection, and it is paid where it can be afforded:
	// 4.05s on the 2s keep-alive bed against the 5.198s that was the shortest
	// silence any dead link in the sweep produced, and 12.05s at the shipped
	// defaults against a stack verdict past 31s.
	//
	// It also subsumes the floor the sweep chose. 2s was the shortest value on
	// the sweep grid that never fired on a working link and always fired on a
	// dead one; this constant alone is that value, and the threshold is this
	// constant plus two non-negative terms, so no configuration can compute a
	// threshold under the floor and there is nothing left for a max() to do.
	silenceSlack = 2 * time.Second

	// ackDelay is the max_ack_delay term of RFC 9002's PTO. DERIVED, not
	// measured, and approximate: quic-go's PTO adds the value the *peer*
	// advertised, and pathstats.Stats does not carry it, so this is the default
	// our own end advertises (quic-go internal/protocol/params.go, MaxAckDelay).
	// A peer advertising more would make the real keep-alive interval longer than
	// this computes; silenceSlack is eighty times this term and absorbs the error.
	ackDelay = 25 * time.Millisecond

	// granularity is the floor RFC 9002 puts under the variance term of the PTO,
	// and quic-go's protocol.TimerGranularity. DERIVED.
	granularity = time.Millisecond
)

// Config is the connection's own configuration, which is what the threshold is a
// function of. None of it is a property of the network.
type Config struct {
	// KeepAlive is the client's configured keep-alive period. Zero means the
	// connection sends nothing of its own accord, so receive silence carries no
	// information and this package will never conclude a path is dead. That is
	// not a safety valve, it is the honest reading: with nothing being asked,
	// silence is what a healthy connection looks like.
	KeepAlive time.Duration

	// IdleTimeout is the negotiated QUIC idle timeout -- the smaller of the two
	// ends' max_idle_timeout, which is what quic-go halves to bound the keep-alive
	// interval. Passing the locally configured value instead is safe in the one
	// direction that matters: a peer with a shorter timeout only shortens the
	// interval, and a threshold computed from the longer one is merely slower to
	// fire, never quicker to fire wrongly. Zero leaves the bound off entirely,
	// which errs the same way.
	IdleTimeout time.Duration

	// Candidates is every address the policy may move to, in the order it should
	// try them. The order is the caller's, because ranking candidates needs a
	// measurement of each one that does not exist yet: nothing a connection can
	// observe about a path it is not using says anything about that path. An empty
	// list means the first detection has nowhere to go and gives up.
	Candidates []netip.AddrPort
}

// Path is the input boundary: everything the policy needs to observe about a
// connection and nothing else.
//
// core/client's PathStatsProvider supplies PathStats and its PathController
// supplies Current; a client satisfies both by type assertion. Joining them into
// one value, and calling PathController.SwitchTo when a decision says to, is the
// wiring's job and is deliberately not here -- a policy that could move the
// connection could not be run over a table.
type Path interface {
	PathStats() (pathstats.Stats, bool)
	Current() net.Addr
}

// Observation is one reading of a Path.
type Observation struct {
	// At is when the reading was taken. Readings are expected in order; a reading
	// older than the one before it is treated as having arrived at the same
	// instant, so a clock that goes backwards cannot manufacture silence.
	At time.Time

	// On is the address the connection is sending to. It is not necessarily the
	// address of the last switch: with the path manager off a QUIC connection also
	// follows the source address of the packets it accepts, which is how it
	// survives a NAT rebinding, and a move the policy did not order restarts the
	// silence clock exactly as one it did.
	On netip.AddrPort

	// Live is PathStats' second return value: false when the client has no
	// connection to report on, which a reconnecting client is between attempts.
	//
	// It is not a liveness signal and must not be read as one. A plain client
	// whose QUIC connection has died goes on answering Live with every counter
	// frozen at its last value, forever. "The numbers stopped moving" is the only
	// form in which death reaches this package, which is the same form a blackhole
	// takes -- so one rule covers both.
	Live bool

	// Stats is the reading. Only PacketsReceived, SmoothedRTT and RTTVariance are
	// read; see the package comment for what the rest were measured to be worth.
	Stats pathstats.Stats
}

// Sample builds an Observation from a Path. It returns false when there is
// nothing to observe: no connection, or a current address that is not an
// IP address and port and so cannot be compared with a candidate.
func Sample(at time.Time, p Path) (Observation, bool) {
	stats, live := p.PathStats()
	if !live {
		return Observation{At: at, Live: false}, true
	}
	on, ok := addrPort(p.Current())
	if !ok {
		return Observation{}, false
	}
	return Observation{At: at, On: on, Live: true, Stats: stats}, true
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case nil:
		return netip.AddrPort{}, false
	case *net.UDPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), ap.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// Action is what the policy decided.
type Action uint8

const (
	// Stay leaves the connection where it is.
	Stay Action = iota
	// Switch moves it to Decision.To.
	Switch
	// GiveUp means there is nothing left to try. The connection stays where the
	// last decision put it, and the caller's remaining options -- reconnect, go
	// and find more candidates, tell the user -- are all outside this package.
	GiveUp
)

func (a Action) String() string {
	switch a {
	case Stay:
		return "stay"
	case Switch:
		return "switch"
	case GiveUp:
		return "give-up"
	}
	return fmt.Sprintf("action(%d)", uint8(a))
}

// Reason says why, in a form a test can assert on rather than a sentence.
type Reason uint8

const (
	// Alive: packets are arriving, or the silence so far is shorter than the
	// threshold. These are the same answer, and deliberately so -- the policy
	// cannot tell a path that is about to come back from one that is not, so the
	// ambiguity is encoded as staying.
	Alive Reason = iota
	// NoKeepAlive: KeepAlive is zero, so the connection asks the far end nothing
	// and silence is not evidence of anything.
	NoKeepAlive
	// NoConnection: there is no connection to observe. A reconnecting client
	// between attempts is in this state, and moving a connection that does not
	// exist is not a thing that can be done.
	NoConnection
	// Silent: nothing has been received for longer than the threshold, on a
	// connection that was asking.
	Silent
	// Exhausted: every candidate has been silent on this connection.
	//
	// It is not latched into every answer, only into the answers a detection
	// would otherwise have acted on: a path that goes on delivering the odd
	// packet still reads Alive in between, so a caller polling a dribbling link
	// sees stay and give-up alternate at the threshold's rhythm. That is the
	// honest reading of it -- the path is neither working nor gone -- and it is
	// the caller's cue that the connection, not the path, is what needs
	// replacing.
	Exhausted
	// NoCandidates: the policy was configured with nowhere to go.
	NoCandidates
)

func (r Reason) String() string {
	switch r {
	case Alive:
		return "alive"
	case NoKeepAlive:
		return "no-keep-alive"
	case NoConnection:
		return "no-connection"
	case Silent:
		return "silent"
	case Exhausted:
		return "exhausted"
	case NoCandidates:
		return "no-candidates"
	}
	return fmt.Sprintf("reason(%d)", uint8(r))
}

// Decision is one answer.
type Decision struct {
	Action Action
	Reason Reason
	// To is the candidate to move to, set only when Action is Switch.
	To netip.AddrPort
	// Silence is how long nothing had been received when the decision was made,
	// and Threshold what it was being compared against. Both are carried so that
	// a log line explains itself and a test can assert the comparison rather than
	// only its outcome.
	Silence, Threshold time.Duration
}

func (d Decision) String() string {
	s := fmt.Sprintf("%s (%s, quiet %v of %v)", d.Action, d.Reason,
		d.Silence.Round(time.Millisecond), d.Threshold.Round(time.Millisecond))
	if d.Action == Switch {
		s += " -> " + d.To.String()
	}
	return s
}

// Threshold is the silence a Selector may read as "this path is dead" on a
// connection with this configuration and these round trips.
//
//	interval  = max(min(KeepAlive, IdleTimeout/2), 1.5*PTO)
//	Threshold = interval + SmoothedRTT + silenceSlack
//
// It is built out of the one thing that makes silence mean anything, which is
// that the connection asks. interval is quic-go's keep-alive interval, copied
// from connection.go's nextKeepAliveTime: the configured period bounded by half
// the negotiated idle timeout, raised to 1.5 times the probe timeout when the
// path is slow enough that the shorter interval would ping faster than the path
// can answer. Being a property of the connection rather than of the network is
// the whole reason a threshold is not a constant: on a test bed's 4s/2s it is
// four seconds and at the shipped 30s/10s it is twelve.
//
// SmoothedRTT is the answer's own travel time, and it is spent here explicitly
// rather than being absorbed into the slack because the measurement says it has
// to be. The gap between packets received on a healthy idle connection is the
// interval plus the round trip -- 2.061s at a 2s keep-alive on a 50ms link,
// 10.061s at 10s -- so a threshold that adds only a fixed slack is a threshold
// that fires on a healthy connection as soon as the path is slower than the
// slack. A path that has rerouted onto a 3s round trip is the case: quic-go
// pings it every 6s and hears back at 9s, and a 3s-based threshold would
// condemn it.
//
// Reading the round trip out of pathstats.Stats has one property worth having on
// purpose: SmoothedRTT freezes on a dead path rather than rising, because an
// estimate only moves when an ack arrives. A dead path cannot inflate the
// threshold that is about to condemn it, and this term costs nothing there.
//
// What it does not fix is the ceiling, and where that ceiling actually falls was
// swept rather than estimated. SmoothedRTT lags a reroute -- it only moves when
// an answer arrives, and after a reroute the answer is what is late -- so for the
// first gap after a path gets slower, the threshold is computed from the round
// trip the path used to have and the gap is made of the round trip it has now.
// The difference has to fit in silenceSlack, and nothing else absorbs it: on the
// 2s keep-alive bed with SmoothedRTT held at 50ms, sweeping the rerouted round
// trip in 50ms steps, the policy stays up to 1.05s and switches from 1.1s
// upwards when the slack is 1s. That is the whole tolerance, so the slack is 2s
// and the tolerance is a reroute to a 2.05s round trip. Past that the policy can
// still call a working path dead, and no passive reading of this connection can
// do better -- the evidence that would exculpate the path is exactly the evidence
// being withheld. The fix is to probe the candidate, and that probe does not
// exist yet.
//
// Under application traffic the same reroute is absorbed with room to spare and
// for a different reason: the gap is then the round trip and not the interval
// plus the round trip. Measured on a live connection over the 2s bed, a step to
// a 1s round trip produced a worst gap of 1.054s against a threshold that
// started at 4.055s and climbed to 6.58s as SmoothedRTT tracked the step. The
// idle case is the one that binds.
//
// Threshold is exported because a caller has to be able to say how long it will
// take to notice, and because a threshold that only exists inside the loop that
// uses it cannot be checked against the bed it was measured on.
//
// It is meaningless when Config.KeepAlive is zero -- quic-go then sends no
// keep-alive and there is no interval for a threshold to sit above. The policy
// does not use it in that case; it stays.
func Threshold(cfg Config, s pathstats.Stats) time.Duration {
	interval := cfg.KeepAlive
	if half := cfg.IdleTimeout / 2; half > 0 && half < interval {
		interval = half
	}
	if slow := 3 * pto(s) / 2; slow > interval {
		interval = slow
	}
	return interval + s.SmoothedRTT + silenceSlack
}

// pto is RFC 9002's probe timeout from the round trips a connection reports,
// which is what quic-go's own PTO(true) computes from the same three quantities.
func pto(s pathstats.Stats) time.Duration {
	return s.SmoothedRTT + max(4*s.RTTVariance, granularity) + ackDelay
}

// Outcome is what happened to a switch the policy asked for. The caller reports
// it, because core/client.PathController is the only thing that knows.
type Outcome uint8

const (
	// Refused: the switch did not happen for a reason particular to the candidate
	// -- an address the transport would not take. The candidate is struck off and
	// the next observation moves on to another one.
	Refused Outcome = iota
	// ConnectionGone: there was no live connection to move. core/client.SwitchTo
	// returns ErrNoConnection for exactly this, and returns it rather than a false
	// success precisely so that a selector can believe it. Nothing this package
	// decides can help a connection that has ended, so the remaining candidates
	// are not worth walking through one silence threshold at a time: it gives up
	// at once and leaves reconnecting to the caller.
	ConnectionGone
)

// A Selector applies the policy to a stream of observations of one connection.
//
// It is not safe for concurrent use; feed it from the goroutine that polls.
type Selector struct {
	cfg Config

	started bool
	// on is where the connection was at the last observation, or where the last
	// ordered switch was aimed.
	on netip.AddrPort
	// quietSince is the clock, and the only hysteresis in the policy. It is reset
	// when a packet arrives, when a switch is ordered, and when the connection
	// underneath changes -- so after a move, a candidate gets a full threshold to
	// prove itself before anything can order another move. That is deliberate and
	// it is not free: every switch costs a round trip before the connection is
	// usable again, plus a congestion controller reset, which is why the policy
	// does not get a second, shorter timer for "the switch did not help".
	quietSince time.Time
	// lastRx is the previous PacketsReceived reading. A reading below it means the
	// connection underneath has been replaced.
	lastRx uint64

	// tried is the candidates already found silent, and exhausted that the list
	// ran out. Both belong to the connection and not to an outage within it: they
	// are cleared when the connection underneath is replaced and at no other
	// time, so the policy walks the candidate list at most once per connection.
	//
	// The rule this replaced put candidates back on the list once some candidate
	// had delivered a packet and then held quiet for a whole threshold. It was
	// falsifiable by one packet: a link delivering one packet per threshold drew
	// 20 switches in 65 seconds through two candidates. See the package comment
	// for why no packet-counting rule separates that link from a healthy idle one.
	tried     map[netip.AddrPort]bool
	exhausted bool

	// pendingFrom and pendingQuiet are the state to put back if the switch just
	// ordered turns out not to have happened.
	pendingFrom  netip.AddrPort
	pendingQuiet time.Time
}

// New returns a Selector that has not seen anything yet.
func New(cfg Config) *Selector {
	// Candidates are normalised here, once, because everything they are later
	// compared against has been. An address that reaches the policy through
	// Observation.On has passed through addrPort, which unmaps it; a candidate
	// list built the ordinary way -- net.ResolveUDPAddr(...).AddrPort(), or
	// anything that went near a dual-stack socket -- carries the v4-in-v6 form.
	// Comparing the two forms is always false, so the candidate the connection
	// is sitting on never matches the list, tried never records it, and the
	// policy walks the same candidates for as long as the silence lasts.
	// Measured before this: twenty-two switches in ninety seconds.
	cfg.Candidates = slices.Clone(cfg.Candidates)
	for i, c := range cfg.Candidates {
		cfg.Candidates[i] = netip.AddrPortFrom(c.Addr().Unmap(), c.Port())
	}
	return &Selector{cfg: cfg, tried: make(map[netip.AddrPort]bool)}
}

// Observe takes one reading and answers.
//
// The caller owes it one thing in return: a Switch decision must either be
// carried out or reported back through SwitchFailed. A caller that quietly does
// neither leaves the connection on an address the policy believes it has left,
// and the next reading -- whose On field disagrees -- is indistinguishable from
// a NAT rebinding, which restarts the silence clock and forgives the path.
func (s *Selector) Observe(o Observation) Decision {
	if !o.Live {
		// Nothing to observe and nothing to move. The clock restarts so that a
		// connection which appears later is judged from when it appeared, and the
		// candidates go back on the list: whatever they were found to be, they
		// were found to be it on a connection that no longer exists.
		s.freshConnection(o.At)
		s.on = netip.AddrPort{}
		s.started = false
		return Decision{Action: Stay, Reason: NoConnection}
	}
	if !s.started {
		s.started = true
		s.on = o.On
		s.lastRx = o.Stats.PacketsReceived
		s.restart(o.At)
	}
	if o.At.Before(s.quietSince) {
		// Readings out of order. Silence is measured, never assumed, so a clock
		// that moved backwards produces zero silence rather than negative.
		o.At = s.quietSince
	}
	switch {
	case o.Stats.PacketsReceived < s.lastRx:
		// A counter cannot fall on one connection, so this is a different one --
		// a reconnecting client dialled again underneath us. Nothing the old
		// connection taught us transfers, including which candidates it found
		// silent.
		s.freshConnection(o.At)
		s.on = o.On
	case o.On != s.on:
		// The connection moved without being told to, which a QUIC connection
		// does when it follows the source address of what it accepts. Whatever
		// silence had accumulated belonged to the address it left.
		s.restart(o.At)
		s.on = o.On
	case o.Stats.PacketsReceived > s.lastRx:
		s.quietSince = o.At
	}
	s.lastRx = o.Stats.PacketsReceived

	threshold := Threshold(s.cfg, o.Stats)
	quiet := o.At.Sub(s.quietSince)
	d := Decision{Silence: quiet, Threshold: threshold}

	if quiet < threshold {
		// The path is answering, which is the end of it. Nothing here puts a
		// candidate back on the list: the only thing that does is a new
		// connection, because the only evidence that would justify trying a
		// silent candidate again is a measurement of that candidate, and there
		// is none.
		d.Action, d.Reason = Stay, Alive
		return d
	}

	if s.cfg.KeepAlive <= 0 {
		// The connection asks the far end nothing, so this silence is what a
		// healthy connection looks like and there is nothing to conclude from it.
		d.Action, d.Reason = Stay, NoKeepAlive
		return d
	}
	if len(s.cfg.Candidates) == 0 {
		d.Action, d.Reason = GiveUp, NoCandidates
		return d
	}
	if s.exhausted {
		d.Action, d.Reason = GiveUp, Exhausted
		return d
	}

	s.tried[s.on] = true
	next, ok := s.next()
	if !ok {
		s.exhausted = true
		// The silence clock is not restarted: giving up is a standing answer, and
		// a caller polling every 20ms must not see it flicker back to "stay" a
		// threshold later on a connection where nothing has changed.
		d.Action, d.Reason = GiveUp, Exhausted
		return d
	}
	s.pendingFrom, s.pendingQuiet = s.on, s.quietSince
	s.on = next
	s.restart(o.At)
	d.Action, d.Reason, d.To = Switch, Silent, next
	return d
}

// SwitchFailed reports that the switch the policy last asked for did not happen.
//
// Without it the policy would go on believing the connection had moved, and
// would then wait a whole threshold on a path it was never on before trying
// anything else. With it, the silence that provoked the switch is put back, so
// the next observation reaches the same conclusion again immediately and moves
// on to another candidate.
func (s *Selector) SwitchFailed(to netip.AddrPort, out Outcome) {
	if s.on != to {
		return
	}
	s.tried[to] = true
	s.on = s.pendingFrom
	s.quietSince = s.pendingQuiet
	if out == ConnectionGone {
		s.exhausted = true
	}
}

// next is the first candidate not yet tried on this connection.
func (s *Selector) next() (netip.AddrPort, bool) {
	for _, c := range s.cfg.Candidates {
		if !s.tried[c] && c != s.on {
			return c, true
		}
	}
	return netip.AddrPort{}, false
}

// restart puts the silence clock back to at. Every caller is a point at which
// the address being judged became a different one, so nothing that happened
// before counts either for it or against it.
func (s *Selector) restart(at time.Time) {
	s.quietSince = at
}

// freshConnection is restart plus the whole candidate list back, and it is
// reached only from the two readings that mean the connection itself has been
// replaced: a reading with no connection at all, and a PacketsReceived that has
// fallen. What a candidate was found to be belongs to the connection it was
// found on -- a candidate unreachable from a socket that has since been closed
// says nothing about one that has just been opened -- so a Selector that has run
// out of candidates once must not answer GiveUp on the connection that replaces
// it.
//
// One replacement it cannot see: a client that dials again between two readings
// and whose new connection has already received more packets than the old one
// had. There is no counter that catches that, and in practice the reconnecting
// client is between attempts for far longer than a poll, so the first of the two
// readings arrives.
func (s *Selector) freshConnection(at time.Time) {
	s.restart(at)
	clear(s.tried)
	s.exhausted = false
}
