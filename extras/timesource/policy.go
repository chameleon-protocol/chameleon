package timesource

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"
)

// BuildTimeOverride can be set at link time
// (-X github.com/apernet/hysteria/extras/v2/timesource.BuildTimeOverride=<RFC3339>)
// for builds that carry no VCS stamp, such as release builds from a source
// tarball.
var BuildTimeOverride string

// BuildTime returns the time this binary was built, which is the newest moment
// the local clock can be known to be wrong: no correctly running clock can read
// earlier than the build it is running.
func BuildTime() (time.Time, bool) {
	if BuildTimeOverride != "" {
		if t, err := time.Parse(time.RFC3339, BuildTimeOverride); err == nil {
			return t, true
		}
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return time.Time{}, false
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.time" {
			if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
				return t, true
			}
			break
		}
	}
	return time.Time{}, false
}

// NeedsCorrection reports whether the local clock is provably wrong, i.e. it
// reads earlier than a time the binary is known to postdate. A floor that is
// not known (zero) means we cannot prove anything and must leave the clock
// alone.
//
// This is deliberately the only condition under which network time is fetched
// or adopted. A clock that merely might be wrong is left alone, so an attacker
// controlling the unauthenticated time source can never move a working clock.
func NeedsCorrection(local, floor time.Time) bool {
	return !floor.IsZero() && local.Before(floor)
}

// Bootstrap corrects clk from src if, and only if, the local clock is provably
// wrong per NeedsCorrection. It reports whether a correction was applied.
//
// When the clock is broken and no time source can be reached, the returned
// error is an *ErrClockUnsynced, which spells out for the operator why nothing
// will connect and how to fix it. That case is fatal in practice: the host will
// not be able to establish any connection until its clock is repaired.
func Bootstrap(ctx context.Context, clk *Clock, src Source, floor time.Time) (bool, error) {
	local := clk.Now()
	if !NeedsCorrection(local, floor) {
		return false, nil
	}
	res, err := src.Query(ctx)
	if err != nil {
		return false, &ErrClockUnsynced{Local: local, Floor: floor, Err: err}
	}
	if res.Time.Before(floor) {
		// The source answered, but with a time that is impossible for this
		// binary — a broken or lying server. Adopting it would leave the host
		// just as unusable, with the failure hidden behind an apparent success.
		return false, &ErrClockUnsynced{
			Local: local,
			Floor: floor,
			Err:   fmt.Errorf("%s returned %s, which predates this build", res.Server, res.Time.UTC().Format(time.RFC3339)),
		}
	}
	// Recompute the offset against clk rather than reusing res.Offset: the
	// source measured against the raw system clock, and clk is what callers
	// will read.
	clk.Correct(res.Time.Sub(clk.Now()))
	return true, nil
}

// ErrClockUnsynced reports a local clock that is known to be wrong and could
// not be repaired.
type ErrClockUnsynced struct {
	Local time.Time
	Floor time.Time
	Err   error
}

func (e *ErrClockUnsynced) Error() string {
	return fmt.Sprintf("system clock is unusable: it reads %s, before this build (%s), "+
		"and no out-of-band time source could be reached (%v). "+
		"Packets sent with this clock fall outside the peer's replay window, so no connection can be established. "+
		"Fix the clock, then restart: set it by hand with `date -u -s \"YYYY-MM-DD hh:mm:ss\"`, "+
		"point the time source at an NTP server this host can actually reach "+
		"(a plain-UDP responder on port 53 or 443 works where 123 is blocked), or fit an RTC",
		e.Local.UTC().Format(time.RFC3339), e.Floor.UTC().Format(time.RFC3339), e.Err)
}

func (e *ErrClockUnsynced) Unwrap() error { return e.Err }
