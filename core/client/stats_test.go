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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/core/v2/internal/protocol"
)

// blockedIO is a udpIO that never delivers anything on its own, so the tests
// below can drive feed() directly.
func blockedIO(t *testing.T) (*mockUDPIO, chan *protocol.UDPMessage) {
	io := newMockUDPIO(t)
	ch := make(chan *protocol.UDPMessage)
	io.EXPECT().ReceiveMessage().RunAndReturn(func() (*protocol.UDPMessage, error) {
		m := <-ch
		if m == nil {
			return nil, errors.New("closed")
		}
		return m, nil
	}).Maybe()
	return io, ch
}

// The receive channel filling up is the client's worst silent failure: the
// application sees throughput collapse and nothing anywhere records that we
// were the ones throwing the traffic away.
func TestUDPStatsQueueFull(t *testing.T) {
	io, ch := blockedIO(t)
	defer close(ch)
	stats := &Stats{}
	sm := newUDPSessionManager(io, stats)

	conn, err := sm.NewUDP()
	require.NoError(t, err)
	defer conn.Close()

	msg := func() *protocol.UDPMessage {
		return &protocol.UDPMessage{
			SessionID: 1,
			FragCount: 1,
			Addr:      "example.com:443",
			Data:      []byte("payload"),
		}
	}

	// Nobody is calling Receive, so the channel fills and stays full.
	for range udpMessageChanSize {
		sm.feed(msg())
	}
	assert.Zero(t, stats.UDPRxQueueFull.Load(), "a message that fit should not be counted as dropped")

	sm.feed(msg())
	assert.EqualValues(t, 1, stats.UDPRxQueueFull.Load())

	sm.feed(msg())
	assert.EqualValues(t, 2, stats.UDPRxQueueFull.Load())
	assert.Zero(t, stats.UDPRxNoSession.Load(), "a full queue is not a missing session")
}

func TestUDPStatsNoSession(t *testing.T) {
	io, ch := blockedIO(t)
	defer close(ch)
	stats := &Stats{}
	sm := newUDPSessionManager(io, stats)

	sm.feed(&protocol.UDPMessage{
		SessionID: 55, // never created
		FragCount: 1,
		Addr:      "example.com:443",
		Data:      []byte("payload"),
	})
	assert.EqualValues(t, 1, stats.UDPRxNoSession.Load())
	assert.Zero(t, stats.UDPRxQueueFull.Load())
}
