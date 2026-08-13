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

package server

import "sync/atomic"

// Stats counts what the server threw away or turned away without telling
// anyone. Every counter here corresponds to a code path that deliberately
// produces no error and no log line, either because the protocol requires
// silence (the masquerade) or because the error is not worth failing on.
// Silence towards the network is the point; silence towards the operator is
// how a half-broken server stays half-broken for a week.
//
// Safe for concurrent use. Pass one in through Config to read the counters;
// otherwise Config.fill allocates one and leaves it on the Config.
type Stats struct {
	// MasqFallback counts requests answered by the masquerade handler rather
	// than the proxy. On a public port most of these are scanners and it is a
	// number that only matters as a trend: a server that suddenly serves
	// nothing but masquerade traffic is a server whose clients can no longer
	// authenticate.
	MasqFallback atomic.Uint64

	// MasqAuthFailed is the subset of MasqFallback that arrived as a proper
	// auth request and failed it. Separated from the rest because a wrong
	// password and a stray HTTP probe call for completely different responses,
	// and on the wire they are answered identically on purpose.
	MasqAuthFailed atomic.Uint64

	// UDPRxMalformed counts datagrams that did not parse as a UDP message.
	UDPRxMalformed atomic.Uint64

	// UDPSessionFeedFailed counts inbound UDP messages a session could not
	// deliver to its target - an ACL rejection, an unresolvable address, a
	// write that failed. Individually these are expected and ignored on
	// purpose; a session where every message fails is not, and without the
	// count it is indistinguishable from a session nobody is using.
	UDPSessionFeedFailed atomic.Uint64
}
