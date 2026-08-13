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

package timesource

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSource struct {
	res    Result
	err    error
	called int
}

func (f *fakeSource) Query(ctx context.Context) (Result, error) {
	f.called++
	return f.res, f.err
}

var testFloor = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

func TestBootstrapCorrectsBrokenClock(t *testing.T) {
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	clk, _ := newTestClock(time.Unix(0, 0).UTC())
	src := &fakeSource{res: Result{Server: "a:123", Time: trueTime, Offset: trueTime.Sub(time.Unix(0, 0))}}

	ok, err := Bootstrap(context.Background(), clk, src, testFloor)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, trueTime, clk.Now())
}

// A clock that could be right is never overridden, and the network is not even
// touched: the source is unauthenticated, so letting it move a plausible clock
// would hand an attacker a lever he does not otherwise have.
func TestBootstrapLeavesPlausibleClockAlone(t *testing.T) {
	local := testFloor.Add(24 * time.Hour)
	clk, _ := newTestClock(local)
	src := &fakeSource{res: Result{Time: local.Add(10 * time.Hour)}}

	ok, err := Bootstrap(context.Background(), clk, src, testFloor)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Zero(t, src.called)
	assert.Equal(t, local, clk.Now())
	assert.False(t, clk.Corrected())
}

func TestBootstrapWithoutFloorDoesNothing(t *testing.T) {
	clk, _ := newTestClock(time.Unix(0, 0).UTC())
	src := &fakeSource{res: Result{Time: time.Now()}}

	ok, err := Bootstrap(context.Background(), clk, src, time.Time{})
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Zero(t, src.called)
}

func TestBootstrapUnreachableSourceIsLoud(t *testing.T) {
	clk, _ := newTestClock(time.Unix(0, 0).UTC())
	queryErr := errors.New("no route to host")
	src := &fakeSource{err: queryErr}

	ok, err := Bootstrap(context.Background(), clk, src, testFloor)
	assert.False(t, ok)
	assert.False(t, clk.Corrected())
	require.Error(t, err)
	assert.ErrorIs(t, err, queryErr)

	var unsynced *ErrClockUnsynced
	require.ErrorAs(t, err, &unsynced)
	assert.Equal(t, testFloor, unsynced.Floor)

	// The message is the only thing an operator of a headless box will see, so
	// it has to name the symptom and a way out.
	msg := err.Error()
	assert.Contains(t, msg, "1970-01-01T00:00:00Z")
	assert.Contains(t, msg, "no route to host")
	assert.Contains(t, msg, "date -u -s")
	assert.True(t, strings.Contains(msg, "replay window"), msg)
}

// A server answering with a time that predates the binary is broken or lying;
// adopting it would leave the host unusable while looking like a success.
func TestBootstrapRejectsImpossibleAnswer(t *testing.T) {
	clk, _ := newTestClock(time.Unix(0, 0).UTC())
	src := &fakeSource{res: Result{Server: "liar:123", Time: testFloor.Add(-90 * 24 * time.Hour)}}

	ok, err := Bootstrap(context.Background(), clk, src, testFloor)
	assert.False(t, ok)
	assert.False(t, clk.Corrected())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "predates this build")
}

// The whole chain a no-RTC device runs at boot: an epoch clock, one plain SNTP
// round trip, and an obfuscator-shaped `func() time.Time` that reads real time
// afterwards.
func TestBootstrapEndToEnd(t *testing.T) {
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	clk, _ := newTestClock(time.Unix(0, 0).UTC())
	ex := &fakeExchanger{handlers: map[string]func([]byte) ([]byte, error){
		"ntp:123": func(req []byte) ([]byte, error) { return reply(req, trueTime), nil },
	}}
	src := &SNTPClient{Servers: []string{"ntp:123"}, Exchange: ex, now: clk.Now}

	ok, err := Bootstrap(context.Background(), clk, src, testFloor)
	require.NoError(t, err)
	require.True(t, ok)

	var obfsClock func() time.Time = clk.Now
	assert.WithinDuration(t, trueTime, obfsClock(), time.Second)
}

func TestNeedsCorrection(t *testing.T) {
	assert.True(t, NeedsCorrection(time.Unix(0, 0), testFloor))
	assert.False(t, NeedsCorrection(testFloor, testFloor))
	assert.False(t, NeedsCorrection(testFloor.Add(time.Hour), testFloor))
	assert.False(t, NeedsCorrection(time.Unix(0, 0), time.Time{}), "unknown floor proves nothing")
}

func TestBuildTimeOverride(t *testing.T) {
	old := BuildTimeOverride
	t.Cleanup(func() { BuildTimeOverride = old })

	BuildTimeOverride = "2026-08-01T00:00:00Z"
	got, ok := BuildTime()
	require.True(t, ok)
	assert.Equal(t, testFloor, got.UTC())

	// A garbage override must not be mistaken for a floor of year zero, which
	// would silently disable the whole policy.
	BuildTimeOverride = "yesterday"
	got, ok = BuildTime()
	if ok {
		assert.False(t, got.IsZero())
	}
}
