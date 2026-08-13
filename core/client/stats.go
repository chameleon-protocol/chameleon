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

package client

import (
	"sync/atomic"

	"github.com/chameleon-protocol/chameleon/core/v2/pathstats"
)

// Stats counts what the client threw away without telling anyone.
//
// None of these produce an error, a log line or a retry - the packet simply
// stops existing, and the application sees a stalled connection with no
// explanation. Counting them is what makes the difference between "the network
// is slow" and "our receive queue has been full for ten minutes".
//
// Safe for concurrent use. Pass one in through Config to keep reading it
// across reconnects; otherwise NewClient allocates one and leaves it there.
type Stats struct {
	// UDPRxQueueFull counts inbound UDP messages dropped because the session's
	// receive channel was full, i.e. the application is not reading fast enough
	// (or at all). This is the classic silent degradation: throughput quietly
	// collapses and nothing anywhere says why.
	UDPRxQueueFull atomic.Uint64

	// UDPRxNoSession counts inbound UDP messages addressed to a session we do
	// not have. A few are normal right after a session closes; a stream of them
	// means the two ends disagree about which sessions exist.
	UDPRxNoSession atomic.Uint64

	// UDPRxMalformed counts datagrams that did not parse as a UDP message.
	UDPRxMalformed atomic.Uint64
}

// PathStatsProvider is implemented by clients that can report the health of
// the path they run over.
//
// It is separate from Client rather than a method on it: Client is implemented
// outside this package, and growing that interface breaks every implementation
// at once. Type-assert instead.
type PathStatsProvider interface {
	// PathStats returns the current statistics of the underlying connection.
	// The second return value is false when there is no connection to report
	// on, which a reconnecting client can be in at any time.
	PathStats() (pathstats.Stats, bool)
}

var (
	_ PathStatsProvider = (*clientImpl)(nil)
	_ PathStatsProvider = (*reconnectableClientImpl)(nil)
)
