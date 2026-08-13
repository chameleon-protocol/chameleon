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

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/core/v2/internal/protocol"
)

// The masquerade is supposed to be indistinguishable from a real web server to
// whoever is on the other end. That silence must not extend to the operator: a
// server that has stopped proxying and serves nothing but the masquerade is a
// server whose clients can no longer get in.
func TestMasqFallbackCounted(t *testing.T) {
	served := 0
	config := &Config{
		Stats: &Stats{},
		MasqHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served++
			w.WriteHeader(http.StatusOK)
		}),
	}
	h := &h3sHandler{config: config}

	for i := range 3 {
		rec := httptest.NewRecorder()
		h.masqHandler(rec, httptest.NewRequest(http.MethodGet, "/index.html", nil))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.EqualValues(t, i+1, config.Stats.MasqFallback.Load())
	}
	assert.Equal(t, 3, served, "the masquerade handler should still be reached")
}

func TestMasqFallbackCountedWithoutHandler(t *testing.T) {
	config := &Config{Stats: &Stats{}}
	h := &h3sHandler{config: config}

	rec := httptest.NewRecorder()
	h.masqHandler(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.EqualValues(t, 1, config.Stats.MasqFallback.Load())
}

// A session that fails every write to its target is indistinguishable from an
// idle session unless the failures are counted somewhere. The errors stay
// ignored - some are genuinely transient - but they stop being invisible.
func TestUDPSessionFeedFailedCounted(t *testing.T) {
	io := newMockUDPIO(t)
	eventLogger := newMockUDPEventLogger(t)
	stats := &Stats{}
	sm := newUDPSessionManager(io, eventLogger, stats, 10*time.Second)

	msg := &protocol.UDPMessage{
		SessionID: 42,
		FragCount: 1,
		Addr:      "address1.com:9000",
		Data:      []byte("hello"),
	}
	udpConn := newMockUDPConn(t)
	closed := make(chan struct{})
	eventLogger.EXPECT().New(msg.SessionID, msg.Addr).Return().Once()
	io.EXPECT().Hook(msg.Data, &msg.Addr).Return(nil).Once()
	io.EXPECT().UDP(msg.Addr).Return(udpConn, nil).Once()
	udpConn.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, string, error) {
		<-closed
		return 0, "", errors.New("closed")
	}).Maybe()
	udpConn.EXPECT().Close().RunAndReturn(func() error {
		close(closed)
		return nil
	}).Once()
	udpConn.EXPECT().WriteTo(msg.Data, msg.Addr).Return(0, errors.New("network unreachable")).Twice()

	sm.feed(msg)
	assert.EqualValues(t, 1, stats.UDPSessionFeedFailed.Load())

	sm.feed(msg)
	assert.EqualValues(t, 2, stats.UDPSessionFeedFailed.Load())
	require.Equal(t, 1, sm.Count(), "a failing write must not tear the session down")

	eventLogger.EXPECT().Close(msg.SessionID, nil).Return().Once()
	sm.cleanup(false)
	assert.Zero(t, sm.Count())
}
