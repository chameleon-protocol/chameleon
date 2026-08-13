//go:build linux

package linkmon

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	platformWatch = watchNetlink
	platformSource = "netlink"
}

// netlinkBufferSize is one read. A read on a netlink socket returns whole
// messages and truncates whatever does not fit, so the buffer has to be
// larger than the biggest RTM_NEWLINK the kernel will produce. 8 KiB is the
// size the kernel itself recommends for route dumps.
const netlinkBufferSize = 8192

// watchNetlink subscribes to the kernel's link and address multicast groups.
// Route groups are deliberately left out; see the package documentation.
func watchNetlink(ctx context.Context, raw chan<- Change) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	err = unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR,
	})
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("netlink bind: %w", err)
	}
	f, err := pollableFile(fd, "netlink")
	if err != nil {
		return err
	}
	defer f.Close()
	// Closing the file is what interrupts the read below; there is no other
	// way to cancel it.
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()

	buf := make([]byte, netlinkBufferSize)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, unix.ENOBUFS) {
				// The socket's receive buffer overflowed and the kernel threw
				// away notifications we will never see. Giving up the socket
				// here would be exactly backwards: the overflow happens when
				// the network is churning hardest, which is when being told
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
			return fmt.Errorf("netlink read: %w", err)
		}
		// The message walk comes from syscall rather than x/sys/unix, which
		// does not export one; the constants below still come from
		// x/sys/unix, which is the one that stays current.
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			// A message we cannot parse is not a reason to give up the
			// socket; the next one is probably fine.
			continue
		}
		var c Change
		for _, msg := range msgs {
			switch msg.Header.Type {
			case unix.RTM_NEWLINK, unix.RTM_DELLINK:
				c |= ChangeLink
			case unix.RTM_NEWADDR, unix.RTM_DELADDR:
				c |= ChangeAddr
			}
		}
		if c == 0 {
			continue
		}
		select {
		case raw <- c:
		case <-ctx.Done():
			return nil
		}
	}
}
