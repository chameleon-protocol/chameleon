package harness

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/chameleon-protocol/chameleon/core/v2/client"
	"github.com/chameleon-protocol/chameleon/core/v2/pathstats"

	"github.com/chameleon-protocol/chameleon/tests/v2/netem"
)

// An Observation runs load across a link that changes underneath it and records
// two things at once: what the transport's own health counters did, and what
// the application saw. It exists to answer the question a Selector has to
// answer -- "is this path dead, and dead in a way that switching would fix?" --
// with measurements instead of intuition.
//
// The hard rule the whole file is built around: the two record streams are kept
// apart. Everything in PathSample and Exchange is visible to a caller of the
// core client through client.PathStatsProvider and through ordinary tunnel
// errors. Everything in netem's own counters is ground truth that only the test
// bed has, and it is used to confirm that the fault happened -- never to
// characterise the failure. Mixing the two produces a detector that cannot be
// built.
type Observation struct {
	// Bulk selects the load pattern. false runs a small request/response every
	// Gap, which is the interactive case and the one where the connection is
	// nearly idle when the fault lands. true streams as fast as the link allows,
	// which keeps data in flight in both directions at the moment of the cut --
	// the two differ in what the *peer* has queued, and that turned out to
	// matter (see the one-way results).
	Bulk bool

	// Gap is the pause between request/response exchanges when Bulk is false.
	Gap time.Duration

	// Payload is the size of each exchange's request when Bulk is false.
	Payload int

	// ExchangeTimeout bounds one exchange. An exchange that exceeds it is
	// recorded as failed and the tunnelled connection is thrown away, so the
	// next exchange starts from a fresh stream: a stalled stream must not stop
	// the observation, only fail one sample of it.
	ExchangeTimeout time.Duration

	// MaxExchanges caps how many exchanges the load performs, zero meaning
	// unbounded. Once the cap is reached the loader stops sending but holds its
	// tunnelled connection open until the observation ends, so what is being
	// observed is an idle application on a live connection rather than a
	// teardown -- which is the state most of a censored user's session is
	// actually in, and the state in which the only thing that produces evidence
	// of the far end is the QUIC keep-alive. Ignored when Bulk is set.
	MaxExchanges int

	// Sample is the interval at which PathStats() is read.
	Sample time.Duration

	// Duration is the whole observation, fault included.
	Duration time.Duration

	// FaultAt is when Fault replaces the link profile, measured from the start.
	// The window before it is the control for the window after it.
	FaultAt time.Duration

	// Fault is the profile the link becomes at FaultAt. Leaving it zero-valued
	// with the same content as the starting profile is the no-fault control,
	// and every scenario needs one: without it there is no noise floor and any
	// gap in the counters looks like a signal.
	Fault netem.Profile
}

// settleWindow is how long after the fault the ground-truth snapshot is taken.
// It covers the one-way delay of the profiles the failure cases use -- 25ms on
// a 50ms link -- with room to spare, and stops well short of the part of the
// failure being measured.
//
// It does not cover a link whose one-way delay exceeds it, so Delivered's
// residual can still count a datagram offered before the snapshot and delivered
// after: on the 1s reroute the log shows a handful more delivered than offered.
// That only matters for cases that were alive anyway, where the assertion is
// "something got through" rather than a count.
const settleWindow = 300 * time.Millisecond

// PathSample is one reading of the health surface the core exposes.
//
// OK is false when the client has no connection to report on. Note what it does
// *not* mean: a plain (non-reconnecting) client whose QUIC connection has died
// still answers with OK true and with the counters frozen at their last values,
// because pathstats.FromQUIC reads a connection object that outlives the
// connection. "The numbers stopped moving" is therefore the only form in which
// death reaches a caller of this API.
type PathSample struct {
	At    time.Duration
	Stats pathstats.Stats
	OK    bool
}

// Exchange is one application-visible round trip through the tunnel.
//
// At and Done are both recorded because they differ by seconds in exactly the
// cases this file is about: opening a tunnelled stream takes no deadline of its
// own -- core/client's TCP() blocks in ReadTCPResponse until the QUIC
// connection itself gives up -- so the moment a caller learns anything is Done,
// never At. A measurement that reported At would credit the stack with a
// detection it had not made yet.
type Exchange struct {
	At   time.Duration
	Done time.Duration
	RTT  time.Duration
	Err  error
	Gone bool // Err means the QUIC connection itself is finished
}

// Report is everything one Observation recorded.
type Report struct {
	Samples   []PathSample
	Exchanges []Exchange
	// FaultAt is when the link actually changed, which is the origin every
	// duration in a Signature is measured from.
	FaultAt time.Duration
	// Before, Settled and After are the netem counters at the fault, shortly
	// after it, and at the end. They are ground truth -- proof that the scenario
	// did what it said -- and must not appear in a detector.
	//
	// Settled exists because a delay link is a pipe with datagrams inside it. A
	// blackhole applied at the fault still delivers whatever was already in
	// flight, so Before-to-After makes a blackhole look like it delivered
	// packets, and can even make deliveries exceed offers when the pipe drains
	// across the window boundary. Ground truth is taken from Settled onward,
	// once the pipe is empty.
	Before, Settled, After netem.Stats
}

// Observe runs o and returns what it recorded.
func (e *Env) Observe(o Observation) Report {
	e.T.Helper()
	if o.Sample <= 0 {
		o.Sample = 20 * time.Millisecond
	}
	if o.ExchangeTimeout <= 0 {
		o.ExchangeTimeout = 2 * time.Second
	}
	if o.Payload <= 0 {
		o.Payload = probePayload
	}

	provider, ok := e.Client.(client.PathStatsProvider)
	if !ok {
		e.T.Fatalf("client does not report path stats")
	}

	origin := time.Now()
	stop := make(chan struct{})
	rep := Report{FaultAt: o.FaultAt}

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(o.Sample)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			// Sampling from a goroutine of our own is sound, which had to be
			// checked rather than assumed: PathStats reaches through to
			// quic-go's ConnectionStats, whose six counters and four RTT fields
			// are every one of them an atomic.Int64 or atomic.Uint64
			// (internal/utils/connstats.go and rtt_stats.go). Confirmed with
			// -race on the host, where cgo is available.
			s, live := provider.PathStats()
			mu.Lock()
			rep.Samples = append(rep.Samples, PathSample{At: time.Since(origin), Stats: s, OK: live})
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, x := range e.runLoad(o, origin, stop) {
			mu.Lock()
			rep.Exchanges = append(rep.Exchanges, x)
			mu.Unlock()
		}
	}()

	time.Sleep(max(0, o.FaultAt-time.Since(origin)))
	rep.Before = e.Ctrl.Stats()
	e.Ctrl.Set(o.Fault)
	rep.FaultAt = time.Since(origin)

	time.Sleep(max(0, rep.FaultAt+settleWindow-time.Since(origin)))
	rep.Settled = e.Ctrl.Stats()

	time.Sleep(max(0, o.Duration-time.Since(origin)))
	close(stop)
	wg.Wait()
	rep.After = e.Ctrl.Stats()
	return rep
}

// tunnel is what both load patterns need from a tunnelled connection.
type tunnel interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

// runLoad keeps traffic on the connection until stop closes, returning one
// Exchange per attempt.
//
// A failed exchange discards its tunnelled connection rather than ending the
// load. That is deliberate: a stream that times out under 30% loss says nothing
// about whether the *path* is finished, and a loader that stopped at the first
// timeout would report every impairment as an outage.
func (e *Env) runLoad(o Observation, origin time.Time, stop <-chan struct{}) []Exchange {
	if o.Bulk {
		return e.runBulk(o, origin, stop)
	}
	var out []Exchange
	payload := make([]byte, o.Payload)
	buf := make([]byte, o.Payload)

	var conn tunnel
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	for {
		select {
		case <-stop:
			return out
		default:
		}
		if o.MaxExchanges > 0 && len(out) >= o.MaxExchanges {
			// Done sending, but still here: the tunnelled connection stays open
			// and is closed by the deferred Close when the observation ends.
			<-stop
			return out
		}
		at := time.Since(origin)
		if conn == nil {
			c, err := e.Client.TCP(e.TCPEcho)
			if err != nil {
				out = append(out, Exchange{At: at, Done: time.Since(origin), Err: err, Gone: isConnectionGone(err)})
				// A client whose connection is finished fails to open a stream
				// immediately, so without this the loop would spin.
				time.Sleep(o.Gap + 20*time.Millisecond)
				continue
			}
			conn = c
		}
		_ = conn.SetDeadline(time.Now().Add(o.ExchangeTimeout))
		start := time.Now()
		err := exchange(conn, payload, buf)
		if err != nil {
			out = append(out, Exchange{At: at, Done: time.Since(origin), Err: err, Gone: isConnectionGone(err)})
			_ = conn.Close()
			conn = nil
			continue
		}
		out = append(out, Exchange{At: at, Done: time.Since(origin), RTT: time.Since(start)})
		if o.Gap > 0 {
			time.Sleep(o.Gap)
		}
	}
}

// runBulk keeps a chunk pump running in both directions: a writer that never
// waits for a reply and a reader that consumes what comes back.
//
// This is not the request/response loader with a bigger payload, and the
// difference is the whole point of having both. A request/response loader is
// application-limited -- one chunk outstanding, so the congestion controller is
// never the thing deciding how much goes on the wire, and a fixed-rate
// controller looks exactly like a loss-responsive one. Only a sender that
// always has data queued can show what Brutal does that BBR does not.
func (e *Env) runBulk(o Observation, origin time.Time, stop <-chan struct{}) []Exchange {
	var out []Exchange
	chunk := make([]byte, throughputChunk)
	back := make([]byte, throughputChunk)

	var (
		conn      tunnel
		writeDone chan struct{}
	)
	drop := func() {
		if conn != nil {
			_ = conn.Close()
			<-writeDone
			conn, writeDone = nil, nil
		}
	}
	defer drop()

	for {
		select {
		case <-stop:
			drop()
			return out
		default:
		}
		at := time.Since(origin)
		if conn == nil {
			c, err := e.Client.TCP(e.TCPEcho)
			if err != nil {
				out = append(out, Exchange{At: at, Done: time.Since(origin), Err: err, Gone: isConnectionGone(err)})
				time.Sleep(50 * time.Millisecond)
				continue
			}
			conn = c
			writeDone = make(chan struct{})
			go func(c tunnel, done chan struct{}) {
				defer close(done)
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}(conn, writeDone)
		}
		_ = conn.SetDeadline(time.Now().Add(o.ExchangeTimeout))
		start := time.Now()
		_, err := io.ReadFull(conn, back)
		done := time.Since(origin)
		if err != nil {
			out = append(out, Exchange{At: at, Done: done, Err: err, Gone: isConnectionGone(err)})
			drop()
			continue
		}
		out = append(out, Exchange{At: at, Done: done, RTT: time.Since(start)})
	}
}

func exchange(conn io.ReadWriter, req, resp []byte) error {
	if _, err := conn.Write(req); err != nil {
		return err
	}
	_, err := io.ReadFull(conn, resp)
	return err
}

// Never is the value of a Signature field for an event that did not happen
// inside the observation. Zero cannot mean that: zero is "at the fault", which
// is a real and common answer.
const Never time.Duration = -1 << 62

// Signature is what the failure looked like through the only window a Selector
// has: readings of client.PathStatsProvider, plus whether the application's own
// exchanges completed. Nothing here is derived from the netem profile or from
// netem's counters, so a detector that keys on any of these fields is a
// detector that could actually be built.
//
// Every duration is measured from the fault, so a negative value means the
// event happened before it.
type Signature struct {
	// RxQuietAt is when PacketsReceived last increased: the moment the far end
	// stopped producing evidence that it is there. It is not itself a detection
	// time -- a detector only knows this in hindsight -- but it is the earliest
	// instant any receive-side detector could possibly fire from, so it bounds
	// every one of them from below.
	RxQuietAt time.Duration
	// RxGapMax is the longest run after the fault in which PacketsReceived did
	// not increase. On a healthy link it is the noise floor, and it is what sets
	// the floor under any silence threshold: a threshold below the healthy
	// RxGapMax is a false-positive generator.
	RxGapMax time.Duration
	// RxAfter is how many packets arrived after the fault at all.
	RxAfter uint64

	// TxAfter is how many packets the stack sent after the fault, and TxSpan is
	// how long it kept sending. These describe what the congestion controller
	// and the loss-recovery timers did, not what the path did, which is why no
	// detector may key on them alone.
	TxAfter uint64
	TxSpan  time.Duration

	// LostDelta is the change in PacketsLost across the post-fault window and
	// LostStepMin the most negative single-interval change. Both stay at zero
	// whenever core/client has replaced the congestion controller, which is
	// every shipped configuration: quic-go writes PacketsLost only from its own
	// sender. Configure CongestionConfig.Type "reno" and they move. See
	// TestPacketsLostNeedsTheControllerWeReplace, and do not design a detector
	// around them.
	LostDelta   int64
	LostStepMin int64

	// FreshRTT counts post-fault samples in which LatestRTT changed, i.e. an ack
	// arrived and produced a new RTT sample. Zero means nothing we sent since
	// the fault has been acknowledged.
	FreshRTT int

	SRTTBefore, SRTTAfter time.Duration
	// MinRTTBefore and MinRTTAfter are quic-go's running minimum, which by
	// definition never rises. A path that reroutes onto a longer one keeps the
	// old MinRTT for the life of the connection, so the documented reading of
	// SmoothedRTT-MinRTT as "the bufferbloat on the path" silently becomes
	// wrong after a reroute.
	MinRTTBefore, MinRTTAfter time.Duration

	// LastGood is when the last application exchange completed, FirstFail when
	// the first one failed, and GoneAt when one first reported the QUIC
	// connection itself finished -- all measured at completion, not at the
	// attempt's start. Never if it did not happen.
	LastGood  time.Duration
	FirstFail time.Duration
	GoneAt    time.Duration

	// OKFalseAt is when PathStats() first reported that there was no connection
	// to read on. Never for a plain client even after its connection has died,
	// because pathstats.FromQUIC reads a connection object that outlives the
	// connection.
	OKFalseAt time.Duration
}

// Signature derives the detector's-eye view of a Report.
func (r Report) Signature() Signature {
	sig := Signature{
		RxQuietAt: Never, LastGood: Never, FirstFail: Never,
		GoneAt: Never, OKFalseAt: Never,
	}
	var (
		gapStart   = r.FaultAt
		lastTx     = r.FaultAt
		prev       PathSample
		havePrev   bool
		baseline   pathstats.Stats
		haveBase   bool
		prevLost   int64
		lostAtBase int64
	)
	for _, s := range r.Samples {
		if s.At < r.FaultAt {
			prev, havePrev = s, true
			continue
		}
		if !haveBase {
			// The last sample before the fault is the "before" reading, and the
			// deltas start from it.
			baseline = s.Stats
			if havePrev {
				baseline = prev.Stats
			}
			haveBase = true
			sig.SRTTBefore, sig.MinRTTBefore = baseline.SmoothedRTT, baseline.MinRTT
			lostAtBase, prevLost = int64(baseline.PacketsLost), int64(baseline.PacketsLost)
			prev = s
			continue
		}
		if s.Stats.PacketsReceived > prev.Stats.PacketsReceived {
			if d := s.At - gapStart; d > sig.RxGapMax {
				sig.RxGapMax = d
			}
			gapStart = s.At
			sig.RxQuietAt = s.At - r.FaultAt
		}
		if s.Stats.PacketsSent > prev.Stats.PacketsSent {
			lastTx = s.At
		}
		if s.Stats.LatestRTT != prev.Stats.LatestRTT {
			sig.FreshRTT++
		}
		if step := int64(s.Stats.PacketsLost) - prevLost; step < sig.LostStepMin {
			sig.LostStepMin = step
		}
		prevLost = int64(s.Stats.PacketsLost)
		if !s.OK && sig.OKFalseAt == Never {
			sig.OKFalseAt = s.At - r.FaultAt
		}
		prev = s
	}
	if len(r.Samples) > 0 {
		last := r.Samples[len(r.Samples)-1]
		if d := last.At - gapStart; d > sig.RxGapMax {
			sig.RxGapMax = d
		}
		sig.SRTTAfter, sig.MinRTTAfter = last.Stats.SmoothedRTT, last.Stats.MinRTT
		if haveBase {
			sig.RxAfter = last.Stats.PacketsReceived - baseline.PacketsReceived
			sig.TxAfter = last.Stats.PacketsSent - baseline.PacketsSent
			sig.LostDelta = int64(last.Stats.PacketsLost) - lostAtBase
		}
	}
	if sig.RxQuietAt == Never {
		// Nothing arrived after the fault at all: the newest evidence is
		// whatever the pre-fault window left, so the quiet started at the fault.
		sig.RxQuietAt = 0
	}
	sig.TxSpan = lastTx - r.FaultAt

	for _, x := range r.Exchanges {
		if x.Err == nil {
			sig.LastGood = x.Done - r.FaultAt
			continue
		}
		if x.Done < r.FaultAt {
			continue
		}
		if sig.FirstFail == Never {
			sig.FirstFail = x.Done - r.FaultAt
		}
		if x.Gone && sig.GoneAt == Never {
			sig.GoneAt = x.Done - r.FaultAt
		}
	}
	return sig
}

func (s Signature) String() string {
	return fmt.Sprintf(
		"rx-quiet-at=%s rx-gap-max=%s rx-after=%d tx-after=%d tx-span=%s "+
			"lost-delta=%+d lost-step-min=%+d fresh-rtt=%d "+
			"srtt=%s->%s minrtt=%s->%s last-good=%s first-fail=%s gone=%s",
		dur(s.RxQuietAt), dur(s.RxGapMax), s.RxAfter, s.TxAfter, dur(s.TxSpan),
		s.LostDelta, s.LostStepMin, s.FreshRTT,
		dur(s.SRTTBefore), dur(s.SRTTAfter), dur(s.MinRTTBefore), dur(s.MinRTTAfter),
		dur(s.LastGood), dur(s.FirstFail), dur(s.GoneAt))
}

func dur(d time.Duration) string {
	if d == Never {
		return "never"
	}
	return d.Round(time.Millisecond).String()
}

// DetectAt is when a detector that fires after silence of no packet received
// for that long would have fired, measured from the fault, or Never if it did
// not fire before the observation ended.
//
// This is the whole recommendation in one function: it takes nothing but
// PathStats() readings and a single parameter, and running it over every
// scenario at several values of silence is how the threshold was chosen and how
// its false positives were counted.
func (r Report) DetectAt(silence time.Duration) time.Duration {
	last := r.FaultAt
	var prev PathSample
	var have bool
	for _, s := range r.Samples {
		if have && s.Stats.PacketsReceived > prev.Stats.PacketsReceived {
			last = s.At
		}
		prev, have = s, true
		if s.At < r.FaultAt {
			last = s.At
			continue
		}
		if s.At-last >= silence {
			return s.At - r.FaultAt
		}
	}
	return Never
}

// FalseDetect is DetectAt over the healthy window before the fault. A non-Never
// answer means the threshold fires on a link that nothing has happened to yet,
// which no measurement after the fault can excuse.
func (r Report) FalseDetect(silence time.Duration) time.Duration {
	pre := Report{FaultAt: 0}
	for _, s := range r.Samples {
		if s.At >= r.FaultAt {
			break
		}
		pre.Samples = append(pre.Samples, s)
	}
	return pre.DetectAt(silence)
}

// Delivered is the netem view of what crossed the link once the fault had
// settled: offered is what the endpoint handed to the link, out is what the
// link delivered. It is ground truth for confirming the scenario -- "the
// profile said the uplink was dead, and nothing went up" -- and is deliberately
// not part of Signature.
func (r Report) Delivered() (upOffered, upOut, downOffered, downOut uint64) {
	return r.After.Up.In - r.Settled.Up.In,
		r.After.Up.Out - r.Settled.Up.Out,
		r.After.Down.In - r.Settled.Down.In,
		r.After.Down.Out - r.Settled.Down.Out
}
