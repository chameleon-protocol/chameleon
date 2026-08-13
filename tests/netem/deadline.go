// chameleon -- a censorship-resistant transport
// Copyright (C) 2026 The chameleon authors
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 3 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package netem

import (
	"sync"
	"time"
)

// deadline is the channel-based read deadline a net.PacketConn is expected to
// have. quic-go's Transport.Close interrupts its read loop by setting the
// deadline to the past and then clearing it, so both directions of the
// transition have to work while a read is already blocked.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	expire chan struct{}
}

func newDeadline() *deadline {
	return &deadline{expire: make(chan struct{})}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	closed := false
	select {
	case <-d.expire:
		closed = true
	default:
	}
	if t.IsZero() {
		if closed {
			d.expire = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur <= 0 {
		if !closed {
			close(d.expire)
		}
		return
	}
	if closed {
		d.expire = make(chan struct{})
	}
	ch := d.expire
	d.timer = time.AfterFunc(time.Until(t), func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.expire == ch {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	})
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expire
}
