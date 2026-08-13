//go:build windows

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
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

func init() {
	platformWatch = watchIPHelper
	platformSource = "iphlpapi"
}

// winSink is the channel the callbacks currently deliver to. It is a package
// global because the callbacks cannot carry one: windows.NewCallback burns a
// slot in a small, never-reclaimed per-process table, so the callbacks are
// created once and shared, and the caller context they are registered with is
// a C pointer that must not point at Go memory. The consequence is that only
// one Monitor may use the native watcher at a time, which is all the
// application needs — the second one gets an error and falls back to polling.
type winSink struct {
	ch chan<- Change
}

var activeSink atomic.Pointer[winSink]

var interfaceCallback = sync.OnceValue(func() uintptr {
	return windows.NewCallback(func(callerContext, row, notificationType uintptr) uintptr {
		notifyWin(ChangeLink)
		return 0
	})
})

var addressCallback = sync.OnceValue(func() uintptr {
	return windows.NewCallback(func(callerContext, row, notificationType uintptr) uintptr {
		notifyWin(ChangeAddr)
		return 0
	})
})

// notifyWin runs on a thread pool thread owned by Windows and must never
// block. If the buffer is full the notification is dropped, which is safe:
// a full buffer means the debounce loop already owes the consumer an event,
// so all that is lost is which kind of change it was, never the fact that
// something changed.
func notifyWin(c Change) {
	sink := activeSink.Load()
	if sink == nil {
		return
	}
	select {
	case sink.ch <- c:
	default:
	}
}

// watchIPHelper registers for interface and address change callbacks and
// blocks until the context is done. Windows has no equivalent of the netlink
// link-state groups that is reachable without a callback, so this is the one
// platform where the notification arrives on a thread the Go runtime does not
// own.
func watchIPHelper(ctx context.Context, raw chan<- Change) error {
	sink := &winSink{ch: raw}
	if !activeSink.CompareAndSwap(nil, sink) {
		return errors.New("another link monitor already holds the change callbacks")
	}
	// Ordering matters on the way out: the notifications are cancelled by the
	// defers below, and CancelMibChangeNotify2 waits for in-flight callbacks
	// to return, so by the time this one runs no callback can still be
	// looking at the sink.
	defer activeSink.CompareAndSwap(sink, nil)

	var ifaceHandle windows.Handle
	err := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, interfaceCallback(), nil, false, &ifaceHandle)
	if err != nil {
		return fmt.Errorf("NotifyIpInterfaceChange: %w", err)
	}
	defer windows.CancelMibChangeNotify2(ifaceHandle)

	var addrHandle windows.Handle
	err = windows.NotifyUnicastIpAddressChange(windows.AF_UNSPEC, addressCallback(), nil, false, &addrHandle)
	if err != nil {
		return fmt.Errorf("NotifyUnicastIpAddressChange: %w", err)
	}
	defer windows.CancelMibChangeNotify2(addrHandle)

	<-ctx.Done()
	return nil
}
