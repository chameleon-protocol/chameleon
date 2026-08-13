//go:build darwin || freebsd || netbsd || openbsd || dragonfly

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

package linkmon

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func init() {
	platformWatch = watchRoute
	platformSource = "route socket"
}

// routeBufferSize is one read. Route messages are small — a header plus a
// handful of sockaddrs — and we only ever look at the header, so this only
// has to be large enough that the common ones arrive whole.
const routeBufferSize = 2048

// watchRoute reads the kernel's PF_ROUTE socket. Unlike netlink there is no
// way to subscribe to a subset of the messages, so everything arrives and the
// message type decides what to do with it. Route messages themselves are
// ignored on purpose; see the package documentation.
func watchRoute(ctx context.Context, raw chan<- Change) error {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("route socket: %w", err)
	}
	// The BSDs have no SOCK_CLOEXEC/SOCK_NONBLOCK flags on socket(2), so both
	// have to be set afterwards. The window before CloseOnExec lands is the
	// same one every Go socket has and is not worth a lock.
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return fmt.Errorf("route socket nonblock: %w", err)
	}
	f, err := pollableFile(fd, "route")
	if err != nil {
		return err
	}
	defer f.Close()
	// Closing the file is what interrupts the read below; there is no other
	// way to cancel it.
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()

	buf := make([]byte, routeBufferSize)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, unix.ENOBUFS) {
				// The socket's receive buffer overflowed and the kernel threw
				// away messages we will never see. Giving up the socket here
				// would be exactly backwards: the overflow happens when the
				// network is churning hardest, which is when being told
				// quickly matters most, and the demotion to polling would
				// last for the life of the process. Report the union instead
				// — something changed, we just do not know what — and keep
				// reading. Not unit tested: it needs a real overflow.
				select {
				case raw <- ChangeLink | ChangeAddr:
				case <-ctx.Done():
					return nil
				}
				continue
			}
			return fmt.Errorf("route socket read: %w", err)
		}
		// Every message on the route socket, whichever struct it really is,
		// begins with the same three fields: u_short msglen, u_char version,
		// u_char type. Reading the type byte is enough to classify it, so
		// none of the per-message structs need to be known here.
		if n < 4 {
			continue
		}
		var c Change
		switch buf[3] {
		case unix.RTM_IFINFO:
			c = ChangeLink
		case unix.RTM_NEWADDR, unix.RTM_DELADDR:
			c = ChangeAddr
		default:
			continue
		}
		select {
		case raw <- c:
		case <-ctx.Done():
			return nil
		}
	}
}
