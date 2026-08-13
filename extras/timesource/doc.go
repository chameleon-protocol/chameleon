// Package timesource provides a boot-time, out-of-band clock correction for
// devices that have no RTC.
//
// The problem it solves: the packet obfuscators carry a timestamp that the
// peer checks against a narrow replay window (tens of seconds). A device
// whose only route to the internet is the tunnel itself — an OpenWrt router,
// a Pi without a battery — boots with its clock at the Unix epoch, so every
// packet it sends is outside the peer's window. It cannot connect, therefore
// it cannot reach an NTP server, therefore its clock stays at 1970. The
// device is bricked, not merely degraded.
//
// The way out is a time source that does not depend on the tunnel. SNTP is
// used because it is the only widely reachable protocol that carries an
// absolute timestamp at the accuracy the replay window needs. Plain DNS was
// considered and rejected: no DNS response carries a wall-clock time, and the
// closest thing available (DNSSEC RRSIG inception) only brackets the current
// time to the signature's validity period, which is days wide.
//
// # Security boundary
//
// The time obtained here is UNAUTHENTICATED. Anyone who can answer a UDP
// packet on the path — the local network, the censor, a hostile resolver
// pointing the NTP hostname wherever it likes — can choose what time this
// device believes. Nothing in this package is a defense against that, and no
// amount of querying more servers makes it one.
//
// Two rules follow, and both are enforced by this package rather than left to
// callers:
//
//   - Network time is only ever used to repair a clock that is already known
//     to be broken. Bootstrap queries the network only when the local clock
//     reads earlier than a caller-supplied floor (see BuildTime), i.e. when
//     the local clock is provably wrong. A plausible local clock is never
//     overridden, so an attacker cannot use this path to move a working
//     clock.
//   - The result must never be treated as a security boundary. Do not derive
//     certificate validity, token expiry, or any replay/freshness decision
//     that protects this host from a Clock corrected here. Its one job is to
//     get the device close enough to real time that its own outbound packets
//     are accepted, which is a liveness property, not a security one. An
//     attacker who controls it can at worst keep the device offline — which
//     is exactly what they can already do by dropping packets.
//
// # Usage
//
// Clock is the injectable clock. Its Now method is directly assignable to a
// `clock func() time.Time` field, so an obfuscator can be built against it and
// pick up the correction whenever it lands:
//
//	clk := timesource.NewClock()
//	floor, _ := timesource.BuildTime()
//	if _, err := timesource.Bootstrap(ctx, clk, timesource.NewSNTPClient(nil), floor); err != nil {
//		// err is an *ErrClockUnsynced carrying operator instructions
//	}
//	// obfuscator.clock = clk.Now
package timesource
