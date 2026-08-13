//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

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
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// pollableFile hands fd to the Go runtime's network poller, wrapped in an
// *os.File so that a blocked Read can be interrupted by Close.
//
// The deadline probe is not a formality. If the runtime declined to register
// the descriptor, the *os.File still works but stays in blocking mode: Close
// would not interrupt an in-flight Read, and cancelling the context would
// leave a goroutine parked in the kernel for the life of the process. Failing
// here instead turns that silent leak into the documented fallback to
// polling.
//
// pollableFile takes ownership of fd: on error the descriptor is already
// closed.
func pollableFile(fd int, name string) (*os.File, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("%s: invalid descriptor", name)
	}
	if err := f.SetReadDeadline(time.Time{}); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: descriptor is not pollable: %w", name, err)
	}
	return f, nil
}
