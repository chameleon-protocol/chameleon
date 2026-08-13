package harness

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/chameleon-protocol/chameleon/core/v2/client"
	coreErrs "github.com/chameleon-protocol/chameleon/core/v2/errors"

	"github.com/chameleon-protocol/chameleon/tests/v2/metrics"
)

const (
	throughputChunk = 32 << 10
	probePayload    = 32
)

// TCPThroughput streams size bytes to the TCP echo server through the tunnel
// and reads them back, returning the goodput in bytes per second.
//
// Every byte crosses the impaired link twice but is counted once, so the figure
// is one-way goodput of a symmetric load -- the same convention on both sides
// of any before/after comparison, which is all a regression threshold needs.
func (e *Env) TCPThroughput(size int, timeout time.Duration) (float64, error) {
	e.T.Helper()
	conn, err := e.Client.TCP(e.TCPEcho)
	if err != nil {
		return 0, fmt.Errorf("open tunnel: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	chunk := make([]byte, throughputChunk)
	if _, err := rand.Read(chunk); err != nil {
		return 0, err
	}

	start := time.Now()
	writeErr := make(chan error, 1)
	go func() {
		remaining := size
		for remaining > 0 {
			n := min(remaining, len(chunk))
			if _, err := conn.Write(chunk[:n]); err != nil {
				writeErr <- err
				return
			}
			remaining -= n
		}
		writeErr <- nil
	}()

	if _, err := io.CopyN(io.Discard, conn, int64(size)); err != nil {
		return 0, fmt.Errorf("read back: %w", err)
	}
	elapsed := time.Since(start)
	if err := <-writeErr; err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}
	return metrics.Throughput(int64(size), elapsed), nil
}

// TCPLatency measures count request/response round trips over a single
// tunnelled connection, pausing gap between them so that the samples measure
// the path rather than the pipeline depth.
//
// warmup exchanges are performed first and discarded: the first exchange on a
// fresh stream also pays for the proxy dialling the far end.
func (e *Env) TCPLatency(count, warmup int, gap, timeout time.Duration) ([]time.Duration, error) {
	e.T.Helper()
	series, err := e.LatencySeries(Probe{
		Count: count, Warmup: warmup, Gap: gap, Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	samples := make([]time.Duration, len(series))
	for i, s := range series {
		samples[i] = s.RTT
	}
	return samples, nil
}

// Probe describes a request/response load pattern. The zero Payload means the
// small default; set it to model a particular application, such as the ~100
// bytes an interactive shell sends per keystroke burst.
type Probe struct {
	Count   int
	Warmup  int
	Gap     time.Duration
	Payload int
	Timeout time.Duration

	// Stop ends the probe early when it is closed. A probe running alongside a
	// transfer has to stop when the transfer does: once the link goes idle the
	// samples describe an empty pipe, and mixing those into a series about
	// queueing turns the queue into an artefact of when the probe happened to
	// finish. Count then only has to be an upper bound.
	Stop <-chan struct{}
}

// LatencySample is one round trip and when it happened, measured from the first
// non-warmup exchange.
//
// The timestamp is what separates a standing queue from a slow link: a
// controller that builds one shows latency climbing with time, which a
// percentile summary of the same samples cannot express.
type LatencySample struct {
	At  time.Duration
	RTT time.Duration
}

// LatencySeries runs p and returns each round trip with the time it started.
//
// A round trip through the tunnel crosses the impaired link twice. Under a
// symmetric profile the one-way delay is half of it, but only in the mean:
// nothing here can separate the two directions, so a one-way figure derived
// from these samples is an assumption, not a measurement.
func (e *Env) LatencySeries(p Probe) ([]LatencySample, error) {
	e.T.Helper()
	return latencySeries(e.Client, e.TCPEcho, p)
}

// PeerLatencySeries is LatencySeries over a second flow's link.
func (e *Env) PeerLatencySeries(peer *Peer, p Probe) ([]LatencySample, error) {
	e.T.Helper()
	return latencySeries(peer.Client, e.TCPEcho, p)
}

func latencySeries(c client.Client, echo string, p Probe) ([]LatencySample, error) {
	size := p.Payload
	if size <= 0 {
		size = probePayload
	}
	conn, err := c.TCP(echo)
	if err != nil {
		return nil, fmt.Errorf("open tunnel: %w", err)
	}
	defer conn.Close()

	payload := make([]byte, size)
	buf := make([]byte, size)
	samples := make([]LatencySample, 0, p.Count)
	var origin time.Time
	for i := 0; i < p.Warmup+p.Count; i++ {
		select {
		case <-p.Stop:
			return samples, nil
		default:
		}
		if err := conn.SetDeadline(time.Now().Add(p.Timeout)); err != nil {
			return nil, err
		}
		start := time.Now()
		if _, err := conn.Write(payload); err != nil {
			return nil, fmt.Errorf("exchange %d: write: %w", i, err)
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, fmt.Errorf("exchange %d: read: %w", i, err)
		}
		if i >= p.Warmup {
			if origin.IsZero() {
				origin = start
			}
			samples = append(samples, LatencySample{At: start.Sub(origin), RTT: time.Since(start)})
		}
		if p.Gap > 0 {
			time.Sleep(p.Gap)
		}
	}
	return samples, nil
}

// TCPLoadFor streams through the tunnel for d and returns how many payload
// bytes came back.
//
// It is bounded by time where TCPThroughput is bounded by size, which is what a
// fairness measurement needs: two flows that ran over the same interval are
// comparable by the bytes each moved, whereas two fixed-size transfers finish
// at different times and stop competing partway through.
func (e *Env) TCPLoadFor(c client.Client, d time.Duration) (int64, error) {
	e.T.Helper()
	conn, err := c.TCP(e.TCPEcho)
	if err != nil {
		return 0, fmt.Errorf("open tunnel: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(d)
	if err := conn.SetDeadline(deadline.Add(2 * time.Second)); err != nil {
		return 0, err
	}

	chunk := make([]byte, throughputChunk)
	if _, err := rand.Read(chunk); err != nil {
		return 0, err
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if time.Now().After(deadline) {
				return
			}
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}()

	var got int64
	buf := make([]byte, throughputChunk)
	for time.Now().Before(deadline) {
		if err := conn.SetReadDeadline(deadline); err != nil {
			break
		}
		n, err := conn.Read(buf)
		got += int64(n)
		if err != nil {
			break
		}
	}
	close(stop)
	return got, nil
}

// Echo runs one small request/response exchange through the tunnel and reports
// whether it completed within timeout. It is the liveness probe the failover
// measurement is built on.
func (e *Env) Echo(timeout time.Duration) error {
	conn, err := e.Client.TCP(e.TCPEcho)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	payload := []byte("netem-probe-payload-0123456789ab")
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if !bytes.Equal(payload, buf) {
		return errors.New("echo returned different bytes")
	}
	return nil
}

// probe is Echo with a hard bound. Echo's own timeout only covers the data
// exchange: opening the tunnel goes through the client, which blocks on the
// QUIC stack's timeouts and can sit there for seconds. A failover measurement
// has to keep sampling on its own schedule, so an over-long probe is abandoned
// rather than waited on -- it finishes on its own once the stack gives up.
func (e *Env) probe(timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- e.Echo(timeout) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return errProbeTimeout
	}
}

var errProbeTimeout = errors.New("probe did not finish in time")

// Failover is what a link outage cost.
type Failover struct {
	// Dead is how long after the cut the client first reported its connection
	// permanently closed, rather than merely slow. This is the stack's own
	// detection latency: it is governed by the QUIC idle timeout, not by how
	// often the test probes.
	Dead time.Duration
	// Recover is how long after the link came back the first exchange
	// succeeded. This is the number a "switchover within N ms" criterion means.
	Recover time.Duration
	// Outage is the whole gap, cut to first success. It includes the cut
	// duration the caller chose, so it is only comparable across runs that used
	// the same cut.
	Outage time.Duration
	// Probes is how many liveness probes were spent.
	Probes int
}

func (f Failover) String() string {
	return fmt.Sprintf("dead-after=%s recover=%s outage=%s probes=%d",
		f.Dead.Round(time.Millisecond), f.Recover.Round(time.Millisecond),
		f.Outage.Round(time.Millisecond), f.Probes)
}

// MeasureFailover blackholes the link for cut, restores it, and reports how
// long the client took to notice and to come back.
//
// It requires an Env built with Options.Reconnect: a plain client has no way
// back once its QUIC connection is gone, so without it Recover would never
// arrive.
func (e *Env) MeasureFailover(cut, probeTimeout, patience time.Duration) (Failover, error) {
	e.T.Helper()
	var f Failover
	if err := e.Echo(probeTimeout); err != nil {
		return f, fmt.Errorf("link was not healthy before the cut: %w", err)
	}

	cutAt := time.Now()
	e.Ctrl.SetBlackhole(true)
	for time.Since(cutAt) < cut {
		err := e.probe(probeTimeout)
		f.Probes++
		if f.Dead == 0 && isConnectionGone(err) {
			f.Dead = time.Since(cutAt)
		}
		if err == nil {
			// Still alive: nothing in flight yet had to cross the dead link.
			time.Sleep(10 * time.Millisecond)
		}
	}

	restoredAt := time.Now()
	e.Ctrl.SetBlackhole(false)
	for {
		if time.Since(restoredAt) > patience {
			return f, fmt.Errorf("no exchange succeeded within %s of the link coming back", patience)
		}
		err := e.probe(probeTimeout)
		f.Probes++
		if f.Dead == 0 && isConnectionGone(err) {
			f.Dead = time.Since(cutAt)
		}
		if err == nil {
			f.Recover = time.Since(restoredAt)
			f.Outage = time.Since(cutAt)
			return f, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// isConnectionGone reports whether err means the QUIC connection itself is
// finished, as opposed to one exchange having timed out.
func isConnectionGone(err error) bool {
	if err == nil {
		return false
	}
	var closed coreErrs.ClosedError
	if errors.As(err, &closed) {
		return true
	}
	var connect coreErrs.ConnectError
	return errors.As(err, &connect)
}
