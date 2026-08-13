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

package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/chameleon-protocol/chameleon/extras/v2/timesource"
)

// fakeTimeSource stands in for SNTP. It counts queries, because "a plausible
// clock never touches the network" is the security property here, not merely an
// optimisation.
type fakeTimeSource struct {
	queries int
	now     time.Time
	err     error
}

func (f *fakeTimeSource) Query(context.Context) (timesource.Result, error) {
	f.queries++
	if f.err != nil {
		return timesource.Result{}, f.err
	}
	return timesource.Result{Server: "fake:123", Time: f.now}, nil
}

// pastFloor is a build time the running system clock comfortably postdates, so
// nothing is provably wrong.
func pastFloor() time.Time { return time.Now().Add(-24 * time.Hour) }

// futureFloor is a build time the running system clock predates, which is how
// a clock reading 1970 looks from here: provably wrong.
func futureFloor() time.Time { return time.Now().Add(10 * 365 * 24 * time.Hour) }

// A working clock is left alone, and -- the part that matters -- no packet is
// sent to the unauthenticated time source at all. If it were, whoever answers
// it would get a say in the time of every host running this.
func TestBootstrapObfsClockLeavesAPlausibleClockAlone(t *testing.T) {
	log, logs := observedLogger()
	src := &fakeTimeSource{now: time.Now()}

	clk, err := bootstrapObfsClock(context.Background(), log, "salamander-v2", src, pastFloor())

	require.NoError(t, err)
	assert.Nil(t, clk, "a plausible clock should not be replaced")
	assert.Zero(t, src.queries, "the network was queried for a clock that was already fine")
	assert.Zero(t, logs.FilterLevelExact(zapcore.WarnLevel).Len(), "nothing to warn about")
}

// The case this whole path exists for: a host whose clock reads earlier than
// the binary it is running cannot be right, and cannot fix itself, because its
// only route out is the tunnel its broken clock is breaking.
func TestBootstrapObfsClockRepairsAnImpossibleClock(t *testing.T) {
	log, logs := observedLogger()
	floor := futureFloor()
	trueNow := floor.Add(time.Hour)
	src := &fakeTimeSource{now: trueNow}

	clk, err := bootstrapObfsClock(context.Background(), log, "salamander-v2", src, floor)

	require.NoError(t, err)
	require.NotNil(t, clk, "a provably wrong clock should have been corrected")
	assert.Equal(t, 1, src.queries)
	assert.WithinDuration(t, trueNow, clk.Now(), time.Minute,
		"the corrected clock does not read the time the source gave")

	// The system clock is still wrong, and TLS still reads it. Saying so is the
	// difference between one confusing failure and two.
	warns := logs.FilterLevelExact(zapcore.WarnLevel).All()
	require.Len(t, warns, 1)
	assert.Contains(t, warns[0].Message, "TLS")
}

// No time source reachable and a clock that is provably wrong is terminal: the
// host will not complete a single handshake. The caller turns this into a
// non-zero exit, so the error has to carry the repair instructions with it --
// silently retrying forever would bury the one fact the operator needs.
func TestBootstrapObfsClockFailsLoudlyWhenUnreachable(t *testing.T) {
	log, _ := observedLogger()
	src := &fakeTimeSource{err: errors.New("dial udp: network is unreachable")}

	clk, err := bootstrapObfsClock(context.Background(), log, "salamander-v2", src, futureFloor())

	require.Error(t, err)
	assert.Nil(t, clk)
	assert.Equal(t, 1, src.queries)

	var unsynced *timesource.ErrClockUnsynced
	require.ErrorAs(t, err, &unsynced)
	msg := err.Error()
	for _, want := range []string{"date -u -s", "NTP", "replay window"} {
		assert.Contains(t, msg, want, "the operator is not told how to fix this")
	}
}

// A source that answers with a time the binary postdates is lying or broken.
// Adopting it would leave the host just as dead, with the failure hidden.
func TestBootstrapObfsClockRejectsAnImpossibleAnswer(t *testing.T) {
	log, _ := observedLogger()
	floor := futureFloor()
	src := &fakeTimeSource{now: floor.Add(-time.Hour)}

	clk, err := bootstrapObfsClock(context.Background(), log, "salamander-v2", src, floor)

	require.Error(t, err)
	assert.Nil(t, clk)
}

// Only Salamander v2 stamps packets with a wall-clock time the peer checks.
// Aborting startup for the other modes because an NTP server is unreachable
// would break deployments that never cared about the clock.
func TestBootstrapObfsClockOnlyGuardsTimestampedObfs(t *testing.T) {
	for _, obfsType := range []string{"", "plain", "salamander", "gecko", "SALAMANDER"} {
		t.Run(obfsType, func(t *testing.T) {
			log, _ := observedLogger()
			src := &fakeTimeSource{err: errors.New("network is unreachable")}

			clk, err := bootstrapObfsClock(context.Background(), log, obfsType, src, futureFloor())

			require.NoError(t, err, "a clockless obfuscator must not block startup")
			assert.Nil(t, clk)
			assert.Zero(t, src.queries)
		})
	}
	// ...and it is matched however the config spells it.
	assert.True(t, obfsNeedsTimestamps("Salamander-V2"))
}

// Without a build stamp there is no moment the clock can be proven to postdate,
// so nothing may be corrected -- an unauthenticated source must never be given
// the chance to move a clock we cannot show is broken.
func TestBootstrapObfsClockNeedsAFloor(t *testing.T) {
	log, logs := observedLogger()
	src := &fakeTimeSource{now: time.Now()}

	clk, err := bootstrapObfsClock(context.Background(), log, "salamander-v2", src, time.Time{})

	require.NoError(t, err)
	assert.Nil(t, clk)
	assert.Zero(t, src.queries)
	assert.Equal(t, 1, logs.FilterMessageSnippet("no build timestamp").Len(),
		"a build that cannot detect a broken clock should say so")
}

// The clock is repaired before the first connection attempt, but a share URI
// only reveals which obfuscator is in play when it is parsed -- which happens
// during that attempt. Reading it early, without consuming it, is what lets the
// two agree.
func TestResolvedObfsTypeReadsTheShareURI(t *testing.T) {
	tests := []struct {
		name   string
		server string
		obfs   string
		want   string
	}{
		{name: "plain host", server: "example.com:443", obfs: "salamander-v2", want: "salamander-v2"},
		{name: "uri wins", server: "chameleon://auth@example.com/?obfs=salamander-v2", obfs: "", want: "salamander-v2"},
		{name: "chm scheme", server: "chm://auth@example.com/?obfs=salamander-v2", obfs: "", want: "salamander-v2"},
		{name: "uri without obfs", server: "chameleon://auth@example.com/", obfs: "gecko", want: "gecko"},
		{name: "realm address", server: "realm://rv.example.com/abc", obfs: "salamander-v2", want: "salamander-v2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &clientConfig{Server: tt.server, Obfs: clientConfigObfs{Type: tt.obfs}}
			assert.Equal(t, tt.want, c.resolvedObfsType())
			// Reading must not consume: Config() parses the URI itself later.
			assert.Equal(t, tt.server, c.Server)
		})
	}
}

// The obfuscator is only handed a clock when one was actually needed; the
// common case must not pay a lock on the packet path.
func TestObfsClockOptions(t *testing.T) {
	assert.Empty(t, obfsClockOptions(nil))
	assert.Len(t, obfsClockOptions(timesource.NewClock()), 1)
}

// A configured time source overrides the defaults; an empty one falls back to
// them, so an operator whose network blocks UDP/123 can redirect it.
func TestTimeSourceConfigServers(t *testing.T) {
	custom := timeSourceConfig{Servers: []string{"ntp.example.com:53"}, Timeout: 2 * time.Second}
	src, ok := custom.source().(*timesource.SNTPClient)
	require.True(t, ok)
	assert.Equal(t, []string{"ntp.example.com:53"}, src.Servers)
	assert.Equal(t, 2*time.Second, src.Timeout)

	fallback, ok := timeSourceConfig{}.source().(*timesource.SNTPClient)
	require.True(t, ok)
	assert.Equal(t, timesource.DefaultServers, fallback.Servers)
}

func TestBuildTimeFloorIsSaneOrZero(t *testing.T) {
	floor := buildTimeFloor()
	if floor.IsZero() {
		// `go test` builds carry no vcs stamp, which is exactly the "cannot
		// prove anything" case the caller has to tolerate.
		t.Skip("this build carries no VCS timestamp")
	}
	assert.False(t, floor.After(time.Now()), "the build cannot postdate now")
}
