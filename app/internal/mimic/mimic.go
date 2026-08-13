// Package mimic runs Mimic (https://github.com/hack3ric/mimic) as a child
// process for the lifetime of a chameleon process.
//
// Mimic disguises UDP as TCP by rewriting packets in the kernel, transparently
// to the socket. We derive its filter from the address chameleon already knows,
// so users don't have to configure it separately. Installing it is still up to
// them; whether its optional kernel module is loaded is Mimic's business, and
// it says so itself when it needs it.
package mimic

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

type Config struct {
	Enabled bool
	// Interface to attach to. Derived from the route to the peer when empty.
	Interface string
	// XDPMode forces "native" or "skb". Empty lets Mimic decide, which is
	// usually right; some drivers misbehave in native mode and need "skb".
	XDPMode string
	// Path to the mimic executable. Looked up in PATH when empty.
	Path string
	// ExtraArgs is passed through verbatim, for tuning Mimic has no chameleon
	// equivalent of (padding, handshake and keepalive parameters).
	ExtraArgs []string
}

// Role determines which side of the connection we are, which decides both the
// filter's origin and whether this end opens the fake TCP connection.
type Role int

const (
	RoleClient Role = iota
	RoleServer
)

const (
	restartDelayMin = 1 * time.Second
	restartDelayMax = 30 * time.Second
)

// process is one running Mimic, attached and rewriting packets.
type process struct {
	// wait blocks until the process is gone, returning why.
	wait func() error
	// stop asks it to leave and waits for it to detach.
	stop func() error
}

// launchFunc starts one Mimic and returns once it has attached.
type launchFunc func() (*process, error)

// Instance keeps a Mimic running. When Mimic exits on its own the kernel
// detaches its BPF programs with it: from that moment our packets leave as
// plain UDP, while the peer's Mimic keeps answering in TCP shape, which our
// socket never sees. There is no degraded mode to fall back to — the flow is
// dead either way — so the only useful response is to bring Mimic back and let
// the connection re-establish over it.
type Instance struct {
	launch   launchFunc
	logger   *zap.Logger
	delayMin time.Duration
	delayMax time.Duration

	mu      sync.Mutex
	proc    *process
	stopped bool

	closing chan struct{} // closed by Close, to cut a restart delay short
	done    chan struct{} // closed when supervise has returned
}

func startWithBackoff(launch launchFunc, logger *zap.Logger, delayMin, delayMax time.Duration) (*Instance, error) {
	p, err := launch()
	if err != nil {
		return nil, err
	}
	i := &Instance{
		launch:   launch,
		logger:   logger,
		delayMin: delayMin,
		delayMax: delayMax,
		proc:     p,
		closing:  make(chan struct{}),
		done:     make(chan struct{}),
	}
	go i.supervise()
	return i, nil
}

// Close stops Mimic and waits for it to detach.
func (i *Instance) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	if i.stopped {
		i.mu.Unlock()
		<-i.done
		return nil
	}
	i.stopped = true
	p := i.proc
	close(i.closing)
	i.mu.Unlock()
	if p != nil {
		_ = p.stop()
	}
	<-i.done
	return nil
}

func (i *Instance) supervise() {
	defer close(i.done)
	for {
		p := i.current()
		if p == nil {
			return
		}
		err := p.wait()
		if i.closed() {
			return
		}
		i.logger.Error("mimic exited on its own; traffic cannot reach the peer until it is back",
			zap.Error(err))
		if !i.restart() {
			return
		}
	}
}

// restart relaunches Mimic, backing off between attempts. Mimic may well be
// gone for a reason that outlives one attempt (a missing kernel feature, an
// interface that went away), so there is no attempt limit: without Mimic the
// process has nothing to do anyway, and giving up would only make the recovery
// manual. It reports false once Close has been called.
func (i *Instance) restart() bool {
	delay := i.delayMin
	for {
		if !i.sleep(delay) {
			return false
		}
		if delay *= 2; delay > i.delayMax {
			delay = i.delayMax
		}
		p, err := i.launch()
		if err != nil {
			i.logger.Error("failed to restart mimic, retrying", zap.Error(err))
			continue
		}
		if !i.adopt(p) {
			// Close came in while we were launching.
			_ = p.stop()
			return false
		}
		return true
	}
}

// sleep waits for d, reporting false if Close happens first.
func (i *Instance) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-i.closing:
		return false
	case <-t.C:
		return true
	}
}

func (i *Instance) current() *process {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return nil
	}
	return i.proc
}

func (i *Instance) closed() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.stopped
}

func (i *Instance) adopt(p *process) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return false
	}
	i.proc = p
	return true
}
