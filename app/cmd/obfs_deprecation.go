package cmd

import (
	"strings"

	"go.uber.org/zap"
)

// warnDeprecatedObfs logs the startup notice for obfs modes that are kept only
// for existing deployments. chromeParrot reports whether the caller also has
// Chrome QUIC fingerprint parroting on; only the client can parrot, so the
// server always passes false.
//
// The reasoning behind the Gecko notices lives in extras/obfs/gecko.go.
func warnDeprecatedObfs(log *zap.Logger, obfsType string, chromeParrot bool) {
	// Matched exactly as wrapObfs dispatches, so the warning fires when — and
	// only when — the obfuscator actually engages.
	if log == nil || strings.ToLower(obfsType) != "gecko" {
		return
	}
	log.Warn("obfs type \"gecko\" is deprecated and stays only for existing deployments. " +
		"It fragments the QUIC handshake but passes the whole data plane through untouched, " +
		"so it reshapes almost nothing a traffic classifier looks at, and each handshake " +
		"packet becomes up to 8 datagrams that are never retransmitted at the obfs layer: " +
		"5% link loss becomes 9.8% to 33.7% effective handshake packet loss (22.2% on " +
		"average). Prefer obfs type \"salamander\"")
	if chromeParrot {
		log.Warn("gecko and Chrome QUIC fingerprint parroting are opposite bets and cancel " +
			"each other out. Parroting pays real costs to make this client's packets look " +
			"like Chrome QUIC; packet shape is the only part of that disguise which survives " +
			"the obfs wrapper, and gecko then shreds it into randomly sized fragments. " +
			"Pick one: drop obfs type \"gecko\", or set quic.disableChromeParrot to true and " +
			"stop paying for a disguise nothing can see")
	}
}
