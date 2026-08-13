package brutal

import (
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/chameleon-protocol/chameleon/core/v2/internal/congestion/common"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	pktInfoSlotCount = 5 // slot index is based on seconds, so this is basically how many seconds we sample

	// minSampleCount is how many packets the sampling window must hold before
	// the measured ack ratio is trusted enough to send extra bytes on. Below
	// it, the estimate's variance is larger than the correction it would drive:
	// ten samples with two losses says "20% loss" with a confidence interval
	// spanning 0-45%, and over-sending 25% on that guess is worse than not
	// compensating at all. A flow slower than 10 packets/s cannot fill the
	// window, and a flow that slow is not what any bottleneck is queueing for.
	//
	// minSampleCountExit is the same threshold on the way out. Without the gap,
	// a flow hovering at the threshold flips ackRate between 1.00 and 0.80 --
	// a 25% swing in send rate driven by nothing but the sample count.
	minSampleCount     = 50
	minSampleCountExit = 40

	// minAckRate bounds the compensation at 1.25x the declared rate. It is what
	// stops a collapsing path from driving the sender into self-excitation:
	// past 20% loss the compensation is deliberately incomplete.
	minAckRate = 0.8

	// congestionWindowMultiplier is the gain over the bandwidth-delay product.
	// Two is the same gain BBR uses for its own cwnd: one BDP fills the pipe,
	// the second covers ack aggregation, delayed acks and scheduling jitter.
	congestionWindowMultiplier = 2

	// cwndFloorPackets is the smallest window the controller will ask for,
	// matching the initial window of quic-go's own controllers (cubic_sender.go
	// initialCongestionWindow = 32, and bbr's initialCongestionWindowPackets).
	//
	// Without a floor, cwnd = bps x minRTT x 2 collapses on short paths: at a
	// 300us round trip a 1 MB/s declaration works out to less than one datagram,
	// and the connection stalls into the idle timeout because every loss then
	// has to wait for a PTO before anything else may be sent. Measured, the
	// break-even sits exactly at this value: declarations whose window landed
	// near 32 packets ran at the declared rate, three packets ran at 15-28% of
	// it, one packet hung. There is no case in which a sender may have fewer
	// bytes outstanding than a standard controller allows on its first flight.
	cwndFloorPackets = 32

	// congestionRTTRatio and relievedRTTRatio are the delay gate that decides
	// whether loss should be compensated for -- see updateCongestionGate.
	congestionRTTRatio = 1.5
	relievedRTTRatio   = 1.25

	// spuriousLossTrackLimit bounds the memory spent remembering which packet
	// numbers were counted as lost, so that a path that reorders heavily cannot
	// turn the correction into an allocation problem. Entries live at most
	// pktInfoSlotCount seconds.
	spuriousLossTrackLimit = 8192

	debugEnv           = "CHAMELEON_BRUTAL_DEBUG"
	debugPrintInterval = 2
)

var _ congestion.CongestionControl = &BrutalSender{}

// BrutalSender sends at the rate the user declared and does not treat loss as a
// reason to slow down.
//
// # Concurrency
//
// Every method of a congestion controller is called by the QUIC connection's
// run loop, on one goroutine: quic-go reaches the controller only through
// sentPacketHandler.getCongestionControl, whose lock covers reading the pointer
// and not the object behind it. So all the plain fields below -- ackRate,
// pktInfoSlots, maxDatagramSize, the whole of the embedded Pacer -- need no
// synchronisation, and adding some would only cost cache line traffic on the
// per-packet send path.
//
// The exceptions are the two atomics. SetBPS and OnPathChange are called by
// whoever is managing the path (P1's candidate switching), which is not the run
// loop, so what they carry across the goroutine boundary is deliberately kept
// to two scalars. Everything those two want to change about the run loop's own
// state happens in drainPending, on the run loop.
type BrutalSender struct {
	rttStats congestion.RTTStatsProvider

	// bps is the declared rate in bytes per second. Written by SetBPS from any
	// goroutine, read on the send path.
	bps atomic.Uint64
	// pacerReset and pathReset are requests posted by SetBPS and OnPathChange
	// and consumed by drainPending on the run loop.
	pacerReset atomic.Bool
	pathReset  atomic.Bool

	maxDatagramSize congestion.ByteCount
	pacer           *common.Pacer

	pktInfoSlots [pktInfoSlotCount]pktInfo
	ackRate      float64

	// compensating is the latched state of the sample-count gate, and congested
	// the latched state of the delay gate. Both are latched so that a value
	// sitting on a threshold does not make the send rate oscillate.
	compensating bool
	congested    bool

	// pendingECNCE counts ECN-CE reports that arrived through OnCongestionEvent
	// but have not yet been folded into a sampling slot.
	pendingECNCE uint64

	// lostPNs remembers which packet numbers have been counted as lost, so that
	// a later acknowledgement of the same packet can take the count back --
	// see OnCongestionEventEx.
	lostPNs map[congestion.PacketNumber]int64

	// minRTTFloor is the smallest round trip seen since the last OnPathChange.
	// It is only consulted after a path change; before one, the RTTStats
	// lifetime minimum is both correct and better seeded.
	minRTTFloor    time.Duration
	pathHasChanged bool

	disableLossCompensation bool

	debug                 bool
	lastAckPrintTimestamp int64
}

type pktInfo struct {
	Timestamp int64
	AckCount  uint64
	LossCount uint64
	ECNCount  uint64
}

// Stats is a read-only view of what the controller currently believes. It
// exists so that tests can assert on the decisions rather than on their
// second-order effects, and costs nothing in production. Read it from the run
// loop only.
type Stats struct {
	BPS              uint64
	AckRate          float64
	CongestionWindow congestion.ByteCount
	SmoothedRTT      time.Duration
	MinRTT           time.Duration
	// Congested is the delay gate's verdict: the path is queueing, so loss is
	// evidence of congestion and is not compensated for.
	Congested bool
}

// NewBrutalSender returns a sender for a declared rate of bps bytes per second.
// bps must be greater than zero: the pacer divides by it. Both call sites in
// the core only reach this after checking the negotiated rate is non-zero.
func NewBrutalSender(bps uint64, disableLossCompensation bool) *BrutalSender {
	debug, _ := strconv.ParseBool(os.Getenv(debugEnv))
	bs := &BrutalSender{
		maxDatagramSize:         congestion.InitialPacketSize,
		ackRate:                 1,
		lostPNs:                 make(map[congestion.PacketNumber]int64),
		disableLossCompensation: disableLossCompensation,
		debug:                   debug,
	}
	bs.bps.Store(bps)
	// Reading ackRate from inside the closure is safe: the closure runs only
	// from Pacer.Budget and Pacer.TimeUntilSend, both of which are reached only
	// from this type's own run-loop methods, which is the same goroutine that
	// writes ackRate in OnCongestionEventEx.
	bs.pacer = common.NewPacer(func() congestion.ByteCount {
		return congestion.ByteCount(float64(bs.bps.Load()) / bs.ackRate)
	})
	return bs
}

// SetBPS changes the declared rate. It is safe to call from any goroutine.
//
// A zero rate is ignored rather than applied. The pacer divides by the rate, so
// zero is a division by zero on the next send; and "the rate is not known yet"
// is not a thing this controller can express -- a caller in that position wants
// the configured controller, not Brutal set to nothing.
//
// The change is not atomic with respect to what is already in the pacer's
// budget. Dropping from a high rate to a low one takes effect from the next
// pacing decision the run loop makes; drainPending clears the budget that was
// accumulated at the old rate, so at most one datagram leaves at the old pace.
func (b *BrutalSender) SetBPS(bps uint64) {
	if bps == 0 {
		return
	}
	b.bps.Store(bps)
	b.pacerReset.Store(true)
}

// OnPathChange tells the controller that the network path underneath the
// connection has been replaced, so the round trip it has been treating as the
// path's propagation delay no longer describes anything.
//
// It is safe to call from any goroutine. It matters because quic-go's minimum
// round trip is a lifetime minimum that never decays: after a switch to a
// longer path, a stale small minimum would hold the congestion window below the
// new path's bandwidth-delay product and would keep the delay gate permanently
// shut.
func (b *BrutalSender) OnPathChange() {
	b.pathReset.Store(true)
}

// drainPending applies whatever another goroutine has asked for. Run loop only.
func (b *BrutalSender) drainPending() {
	if b.pacerReset.CompareAndSwap(true, false) {
		b.pacer.Reset()
	}
	if b.pathReset.CompareAndSwap(true, false) {
		b.pathHasChanged = true
		b.minRTTFloor = 0
	}
}

func (b *BrutalSender) SetRTTStatsProvider(rttStats congestion.RTTStatsProvider) {
	// Called once, inside the write lock that installs this controller and
	// before the run loop can see it (sent_packet_handler.SetCongestionControl),
	// so there is no writer to race with afterwards.
	b.rttStats = rttStats
}

func (b *BrutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	b.drainPending()
	return b.pacer.TimeUntilSend()
}

func (b *BrutalSender) HasPacingBudget(now monotime.Time) bool {
	b.drainPending()
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *BrutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight <= b.GetCongestionWindow()
}

// GetCongestionWindow returns the ceiling on bytes in flight.
//
// The window is built on the path's minimum round trip and not on the smoothed
// one, which is the single most consequential difference from the original.
// Using the smoothed round trip made the window a rising function of the queue
// it was supposed to bound: the deeper the standing queue, the more bytes the
// sender was allowed to add to it, so the queue grew until the bottleneck's
// buffer tail-dropped. Measured at a 10 MB/s declaration, that reached 26214
// packets in flight at a 1.6s smoothed round trip -- past the point quic-go
// considers any controller should ever reach.
//
// It also has to hold still. On a client imitating Chrome, quic-go sizes the
// packet number from this value (sent_packet_handler.PeekPacketNumber ->
// PacketNumberLengthForHeaderChrome), which puts the window into bytes an
// observer can read without decrypting anything. A window that tracked the
// smoothed round trip made the packet number length a visible function of the
// queue depth, and made it change when the path started losing. Built on the
// minimum round trip, the length is a constant for a given declared rate: the
// static difference remains, the moving one does not.
//
// One shift survives, and is worth naming rather than claiming it away. quic-go
// seeds the minimum round trip at 100ms and replaces it outright with the first
// real sample, so the length can change once, early, when the path's own figure
// arrives. That happened before this change too, on top of the drift that did
// not survive it.
//
// The rate is unaffected -- that is the pacer's job, and it still paces at the
// declared rate. This bounds only how much may be outstanding.
func (b *BrutalSender) GetCongestionWindow() congestion.ByteCount {
	// Below the transport's own timer granularity, the minimum round trip stops
	// describing the path and starts describing the host's scheduler: quic-go
	// paces on a one millisecond clock (MinPacingDelay, and TimerGranularity
	// alongside it), so a sender on a 50us loopback still gets its turn at
	// millisecond intervals and needs a millisecond of bytes outstanding to
	// stay busy. Sizing in flight from the measured 50us instead starves it --
	// measured on the bed, a 64 MB/s declaration over loopback fell to between
	// 52% and 92% of the declared rate, run to run, with the floor binding.
	rtt := max(b.minRTT(), congestion.MinPacingDelay)
	cwnd := congestion.ByteCount(float64(b.bps.Load()) * rtt.Seconds() * congestionWindowMultiplier)
	// Loss compensation deliberately does not divide here, though it used to.
	// The extra bytes compensation puts on the wire are the ones expected to be
	// dropped; they do not need in-flight allowance of their own, and giving
	// them some only deepened the queue by a further 25%.
	if floor := cwndFloorPackets * b.maxDatagramSize; cwnd < floor {
		cwnd = floor
	}
	// The absolute ceiling quic-go applies to each of its own controllers
	// (protocol.MaxCongestionWindowPackets). Brutal was the only controller in
	// the tree without one. It bounds the product of an outlandish declared
	// rate and an outlandish round trip, which the minimum-RTT ceiling above
	// cannot: that one is relative to the path.
	if ceiling := congestion.MaxCongestionWindowPackets * b.maxDatagramSize; cwnd > ceiling {
		cwnd = ceiling
	}
	return cwnd
}

// minRTT is the controller's estimate of the path's propagation delay.
//
// Normally it is quic-go's lifetime minimum. A windowed minimum would be the
// textbook answer to staleness, and it is the wrong one here: a windowed
// minimum is only valid for a sender that periodically drains its own queue,
// which is what BBR's PROBE_RTT and CUBIC's backoff buy. Brutal never backs
// off, so on an over-declared path every sample is queue-inflated, the window
// would ratchet the estimate up to the standing queue's round trip, and the
// congestion window would grow to match -- reinstating the feedback loop this
// change exists to break, only with a longer time constant.
//
// A lifetime minimum cannot inflate. It can only be stale, and staleness has
// exactly one cause worth handling: the path was replaced. OnPathChange says
// so, and from then on the estimate is the minimum of what has been seen since.
func (b *BrutalSender) minRTT() time.Duration {
	if b.pathHasChanged && b.minRTTFloor > 0 {
		return b.minRTTFloor
	}
	return b.rttStats.MinRTT()
}

func (b *BrutalSender) OnPacketSent(sentTime monotime.Time, bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool,
) {
	b.drainPending()
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *BrutalSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount, eventTime monotime.Time,
) {
	// Stub: everything this controller learns from acknowledgements it learns
	// in OnCongestionEventEx, which sees them in batches.
}

// OnCongestionEvent is reached from two unrelated places in quic-go. Ordinary
// loss arrives here with the lost packet's length, and is already accounted for
// through OnCongestionEventEx, which this controller implements. A zero length
// is the other caller: the peer's acknowledgement reported ECN-CE marks.
//
// That mark is the only congestion signal on a path that does not require
// something to have been dropped first, which makes it exactly the evidence the
// delay gate is otherwise inferring from queueing. It is recorded rather than
// acted on immediately, because it belongs in the same sampling window as the
// loss counts.
func (b *BrutalSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount,
) {
	if lostBytes == 0 {
		b.pendingECNCE++
	}
}

func (b *BrutalSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	b.drainPending()
	if b.pathHasChanged && len(ackedPackets) > 0 {
		// A fresh round trip sample belongs to the new path. Only sample where
		// there are acknowledgements: a loss-timer call carries whatever the
		// previous path last measured.
		if latest := b.rttStats.LatestRTT(); latest > 0 && (b.minRTTFloor == 0 || latest < b.minRTTFloor) {
			b.minRTTFloor = latest
		}
	}

	currentTimestamp := int64(time.Duration(eventTime) / time.Second)
	slot := currentTimestamp % pktInfoSlotCount
	if b.pktInfoSlots[slot].Timestamp != currentTimestamp {
		// uninitialized slot or too old, reset
		b.pktInfoSlots[slot] = pktInfo{Timestamp: currentTimestamp}
		b.pruneLostPNs(currentTimestamp)
	}
	b.pktInfoSlots[slot].AckCount += uint64(len(ackedPackets))
	b.pktInfoSlots[slot].LossCount += uint64(len(lostPackets))
	b.pktInfoSlots[slot].ECNCount += b.pendingECNCE
	b.pendingECNCE = 0

	// Take back the packets that were declared lost and then turned up. quic-go
	// detects these (detectSpuriousLosses) but only writes them to the qlog; the
	// controller is never told, so a reordering path -- multipath, ECMP, a
	// wireless hop, or a candidate switch -- permanently reads as a lossy one
	// and gets compensated with 25% more bytes it did not need to send. Loss
	// compensation answering a hallucination is worse than it answering real
	// loss, so the count is corrected here.
	for i := range ackedPackets {
		pn := ackedPackets[i].PacketNumber
		ts, ok := b.lostPNs[pn]
		if !ok {
			continue
		}
		delete(b.lostPNs, pn)
		s := ts % pktInfoSlotCount
		if b.pktInfoSlots[s].Timestamp == ts && b.pktInfoSlots[s].LossCount > 0 {
			b.pktInfoSlots[s].LossCount--
		}
	}
	if len(b.lostPNs) < spuriousLossTrackLimit {
		for i := range lostPackets {
			b.lostPNs[lostPackets[i].PacketNumber] = currentTimestamp
		}
	}

	b.updateAckRate(currentTimestamp)
}

// pruneLostPNs drops entries older than the sampling window, which is as long
// as a correction could still matter: the slot they would credit back has been
// overwritten by then.
func (b *BrutalSender) pruneLostPNs(currentTimestamp int64) {
	for pn, ts := range b.lostPNs {
		if ts <= currentTimestamp-pktInfoSlotCount {
			delete(b.lostPNs, pn)
		}
	}
}

func (b *BrutalSender) SetMaxDatagramSize(size congestion.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
	if b.debug {
		b.debugPrint("SetMaxDatagramSize: %d", size)
	}
}

// updateCongestionGate decides whether the loss being observed is the path
// dropping packets on its own or a queue overflowing.
//
// The loss rate cannot tell the two apart: a satellite hop losing 10% and a
// full buffer tail-dropping 10% produce the same ratio. Queueing delay can.
// Congestion loss is always preceded by a queue -- a buffer has to fill before
// it can overflow -- and random loss does not change the queueing delay at all.
// So a smoothed round trip that has risen well above the path's minimum is the
// available proxy for "this loss is congestion".
//
// When the gate says congested, compensation is withdrawn and the sender goes
// back to exactly the declared rate. It does not go below it. That is the line
// between this and a controller that backs off: Brutal still sends what the
// user asked for, it just stops sending the extra 25% into a queue that is
// already full and would only drop it again.
//
// The two ratios are hysteresis, not a range: the gate shuts at 1.5x the
// minimum round trip and does not reopen until 1.25x. A single threshold makes
// the send rate flip between 1.00x and 1.25x whenever the queue sits near it.
func (b *BrutalSender) updateCongestionGate(ecnCount uint64) {
	// An ECN-CE mark is an explicit statement from the path that it is
	// congested, made without dropping anything. Where a path marks, this is
	// both earlier and more certain than the delay inference; where it does not
	// -- which is most censored networks -- the term is simply zero.
	if ecnCount > 0 {
		b.congested = true
		return
	}
	minRTT := b.minRTT()
	srtt := b.rttStats.SmoothedRTT()
	if minRTT <= 0 || srtt <= 0 {
		b.congested = false
		return
	}
	ratio := float64(srtt) / float64(minRTT)
	if b.congested {
		if ratio < relievedRTTRatio {
			b.congested = false
		}
		return
	}
	if ratio > congestionRTTRatio {
		b.congested = true
	}
}

func (b *BrutalSender) updateAckRate(currentTimestamp int64) {
	minTimestamp := currentTimestamp - pktInfoSlotCount
	var ackCount, lossCount, ecnCount uint64
	for _, info := range b.pktInfoSlots {
		if info.Timestamp < minTimestamp {
			continue
		}
		ackCount += info.AckCount
		lossCount += info.LossCount
		ecnCount += info.ECNCount
	}

	// Kept up to date even when compensation is switched off, so that the
	// controller's own view of the path stays readable through Stats.
	b.updateCongestionGate(ecnCount)
	if b.disableLossCompensation {
		b.ackRate = 1
		return
	}

	total := ackCount + lossCount
	if b.compensating {
		b.compensating = total >= minSampleCountExit
	} else {
		b.compensating = total >= minSampleCount
	}
	if !b.compensating {
		b.ackRate = 1
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("Not enough samples (total=%d, ack=%d, loss=%d, rtt=%d)",
				total, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
		}
		return
	}
	if ackCount == 0 {
		// Nothing at all is getting through. That is a path that has gone away,
		// not a path that is leaking, and compensation's premise -- the route
		// still works, it just drops some fraction -- does not hold. Left to the
		// ratio below this would compute a loss rate of 100%, clamp to the
		// floor, and start sending 25% above the declared rate; and because the
		// sampling window is five seconds long, it would still be doing that at
		// the moment the path came back, which is the worst possible moment to
		// be over-sending.
		b.ackRate = 1
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("No acks in window (loss=%d), not compensating", lossCount)
		}
		return
	}
	if b.congested {
		b.ackRate = 1
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("Queueing detected (srtt=%d, minrtt=%d, ecn=%d), not compensating for loss=%d",
				b.rttStats.SmoothedRTT().Milliseconds(), b.minRTT().Milliseconds(), ecnCount, lossCount)
		}
		return
	}
	rate := float64(ackCount) / float64(total)
	if rate < minAckRate {
		b.ackRate = minAckRate
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("ACK rate too low: %.2f, clamped to %.2f (total=%d, ack=%d, loss=%d, rtt=%d)",
				rate, minAckRate, total, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
		}
		return
	}
	b.ackRate = rate
	if b.canPrintAckRate(currentTimestamp) {
		b.lastAckPrintTimestamp = currentTimestamp
		b.debugPrint("ACK rate: %.2f (total=%d, ack=%d, loss=%d, rtt=%d)",
			rate, total, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
	}
}

// Stats reports the controller's current view. Run loop only.
func (b *BrutalSender) Stats() Stats {
	s := Stats{
		BPS:              b.bps.Load(),
		AckRate:          b.ackRate,
		CongestionWindow: b.GetCongestionWindow(),
		Congested:        b.congested,
	}
	if b.rttStats != nil {
		s.SmoothedRTT = b.rttStats.SmoothedRTT()
		s.MinRTT = b.minRTT()
	}
	return s
}

// InSlowStart and InRecovery are false because this controller has neither
// phase, and nothing in quic-go reads them: outside cubic's own use they are
// only forwarded by the congestion control adapters, and neither
// sentPacketHandler nor the qlog consumes the result.
func (b *BrutalSender) InSlowStart() bool { return false }

func (b *BrutalSender) InRecovery() bool { return false }

// MaybeExitSlowStart is called on every advance of the largest acknowledged
// packet. There is no slow start to exit.
func (b *BrutalSender) MaybeExitSlowStart() {}

// OnRetransmissionTimeout has no caller. quic-go handles timeouts entirely in
// its PTO machinery, which deliberately bypasses congestion control -- probes
// are sent before either CanSend or HasPacingBudget is consulted -- so a
// blackholed path recovers without waiting on anything decided here.
func (b *BrutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}

func (b *BrutalSender) canPrintAckRate(currentTimestamp int64) bool {
	return b.debug && currentTimestamp-b.lastAckPrintTimestamp >= debugPrintInterval
}

func (b *BrutalSender) debugPrint(format string, a ...any) {
	fmt.Printf("[BrutalSender] [%s] %s\n",
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, a...))
}
