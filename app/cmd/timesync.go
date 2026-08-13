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
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/chameleon-protocol/chameleon/extras/v2/obfs"
	"github.com/chameleon-protocol/chameleon/extras/v2/timesource"
)

// timeSourceConfig configures the boot-time clock repair.
//
// A host with no RTC boots at the Unix epoch. With Salamander v2 that is fatal
// and self-sustaining: every packet it sends carries a timestamp decades
// outside the peer's ±30s window, so nothing connects, so the tunnel never
// comes up, so its own NTP client never reaches a server. An OpenWrt router or
// a battery-less Pi whose only route out is this tunnel is bricked, not merely
// degraded. See extras/timesource for the way out and, importantly, for the
// limits of what the unauthenticated time it fetches may be used for.
type timeSourceConfig struct {
	// Servers are host:port, deliberately: where UDP/123 is blocked an
	// operator can point this at an NTP responder on 53 or 443 without
	// touching the code. Empty means timesource.DefaultServers.
	Servers []string `mapstructure:"servers"`
	// Timeout bounds a single server query. Zero means the package default.
	Timeout time.Duration `mapstructure:"timeout"`
}

func (c timeSourceConfig) source() timesource.Source {
	src := timesource.NewSNTPClient(c.Servers)
	src.Timeout = c.Timeout
	return src
}

// obfsNeedsTimestamps reports whether the configured obfuscator stamps packets
// with a wall-clock time the peer checks. Only Salamander v2 does; the other
// modes carry no timestamp, so a wrong clock costs them nothing here and must
// not be allowed to abort startup.
//
// Matched exactly as wrapObfs dispatches.
func obfsNeedsTimestamps(obfsType string) bool {
	return strings.ToLower(obfsType) == "salamander-v2"
}

// bootstrapObfsClock repairs the wall clock the obfuscator stamps packets with,
// and returns the clock to hand it -- or nil when the system clock is good
// enough to use directly, which is the overwhelmingly common case and costs
// nothing on the packet path.
//
// The network is touched only when the local clock reads earlier than floor,
// i.e. when it is provably wrong (see timesource.NeedsCorrection). A clock that
// is merely suspect is left alone, so this path can never be used to move a
// working clock. The correction that comes back is unauthenticated and is used
// for exactly one thing: getting our own packets inside the peer's replay
// window. It is not a security boundary and must never be wired into
// certificate validity, token expiry, or any other freshness check -- see the
// extras/timesource package documentation.
//
// A non-nil error means the clock is broken and could not be repaired. That is
// fatal for the caller: the host will not establish a single connection until
// its clock is fixed, and retrying forever would only hide why.
func bootstrapObfsClock(ctx context.Context, log *zap.Logger, obfsType string, src timesource.Source, floor time.Time) (*timesource.Clock, error) {
	if !obfsNeedsTimestamps(obfsType) {
		return nil, nil
	}
	if floor.IsZero() {
		// No build stamp, so there is no moment the clock can be proven to
		// postdate and nothing may be corrected. Worth saying out loud: on a
		// host that does have a broken clock, this is why it stays broken.
		if log != nil {
			log.Debug("no build timestamp available, skipping clock check; " +
				"a wrong system clock cannot be detected in this build")
		}
		return nil, nil
	}
	clk := timesource.NewClock()
	corrected, err := timesource.Bootstrap(ctx, clk, src, floor)
	if err != nil {
		return nil, err
	}
	if !corrected {
		return nil, nil
	}
	if log != nil {
		log.Warn("system clock was too far in the past to talk to the peer and has been "+
			"corrected from an unauthenticated network time source, for obfuscation "+
			"timestamps only. The system clock itself is still wrong: TLS certificate "+
			"validity is checked against it, so verification may still fail. Fix the "+
			"system clock or fit an RTC",
			zap.Duration("offset", clk.Offset()),
			zap.Time("correctedNow", clk.Now()))
	}
	return clk, nil
}

// buildTimeFloor is the newest moment the local clock can be proven to be wrong
// against: no correctly running clock reads earlier than the build it runs.
// A zero value means the build carries no stamp and nothing can be proven.
func buildTimeFloor() time.Time {
	t, _ := timesource.BuildTime()
	return t
}

// obfsClockOptions turns the bootstrapped clock into obfuscator options. A nil
// clock adds none, leaving the obfuscator on time.Now.
func obfsClockOptions(clk *timesource.Clock) []obfs.SalamanderV2Option {
	if clk == nil {
		return nil
	}
	return []obfs.SalamanderV2Option{obfs.WithClock(clk.Now)}
}

// bootstrapClock repairs this client's clock, or exits with the operator's
// repair instructions when it cannot. Every command that opens a connection has
// to call it before Config(), which is also where the correction has to be
// pinned: Config() runs again on every reconnect and each run builds a fresh
// obfuscator.
//
// Retrying instead of exiting would be worse than useless: the process would
// stay up logging connection failures whose real cause is three layers away.
func (c *clientConfig) bootstrapClock() {
	clock, err := bootstrapObfsClock(context.Background(), logger,
		// The obfuscator can be named by a share URI, which Config() does not
		// parse until the first connection attempt -- too late to be of use.
		c.resolvedObfsType(), c.TimeSource.source(), buildTimeFloor())
	if err != nil {
		logger.Fatal("cannot start with this system clock", zap.Error(err))
	}
	c.clock = clock
}

// bootstrapClock repairs this server's clock, or exits, as for the client.
//
// The mesh has no privileged side: a "server" here is as likely to be another
// RTC-less router as a datacenter host with ntpd. One that boots at the epoch
// rejects every client packet on skew and has every packet it sends rejected in
// turn, which is the same brick the client faces. When the clock is plausible
// -- the case for any host with a working NTP client, which a server usually is
// -- no query is made and this costs nothing.
func (c *serverConfig) bootstrapClock() {
	clock, err := bootstrapObfsClock(context.Background(), logger,
		c.Obfs.Type, c.TimeSource.source(), buildTimeFloor())
	if err != nil {
		logger.Fatal("cannot start with this system clock", zap.Error(err))
	}
	c.clock = clock
}
