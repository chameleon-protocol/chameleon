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
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func observedLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	return zap.New(core), logs
}

// mentionsParrot reports whether an entry is the warning about gecko and
// Chrome parroting being contradictory, rather than the plain deprecation one.
func mentionsParrot(e observer.LoggedEntry) bool {
	return strings.Contains(e.Message, "parroting")
}

func TestWarnDeprecatedObfs(t *testing.T) {
	tests := []struct {
		name         string
		obfsType     string
		chromeParrot bool
		wantWarns    int
		wantParrot   bool
	}{
		{name: "default off", obfsType: "", chromeParrot: true},
		{name: "plain", obfsType: "plain", chromeParrot: true},
		{name: "salamander", obfsType: "salamander", chromeParrot: true},
		{name: "gecko without parrot", obfsType: "gecko", wantWarns: 1},
		{name: "gecko with parrot", obfsType: "gecko", chromeParrot: true, wantWarns: 2, wantParrot: true},
		{name: "gecko mixed case", obfsType: "GeCkO", wantWarns: 1},
		// wrapObfs rejects a padded type as unsupported, so nothing engages.
		{name: "gecko padded", obfsType: "  gecko "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			log, logs := observedLogger()
			warnDeprecatedObfs(log, test.obfsType, test.chromeParrot)

			entries := logs.All()
			assert.Len(t, entries, test.wantWarns)
			parrotWarns := 0
			for _, e := range entries {
				assert.Equal(t, zapcore.WarnLevel, e.Level)
				assert.Contains(t, e.Message, "gecko")
				if mentionsParrot(e) {
					parrotWarns++
				}
			}
			if test.wantParrot {
				assert.Equal(t, 1, parrotWarns, "expected exactly one parrot conflict warning")
			} else {
				assert.Zero(t, parrotWarns)
			}
		})
	}
}

// The deprecation notice has to say why, not just that it is deprecated:
// users deciding whether to migrate need the loss amplification number.
func TestWarnDeprecatedObfsExplainsWhy(t *testing.T) {
	log, logs := observedLogger()
	warnDeprecatedObfs(log, "gecko", false)

	entries := logs.All()
	assert.Len(t, entries, 1)
	msg := entries[0].Message
	assert.Contains(t, msg, "deprecated")
	assert.Contains(t, msg, "33.7%")
	assert.Contains(t, msg, "salamander")
}

func TestWarnDeprecatedObfsNilLogger(t *testing.T) {
	assert.NotPanics(t, func() { warnDeprecatedObfs(nil, "gecko", true) })
}

// Gecko must never engage unless it is explicitly asked for by name.
func TestObfsDefaultDisabled(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer conn.Close()

	client := &clientConfig{}
	wrapped, err := client.wrapObfs(conn)
	assert.NoError(t, err)
	assert.Same(t, conn, wrapped)

	server := &serverConfig{}
	wrapped, err = server.wrapObfs(conn)
	assert.NoError(t, err)
	assert.Same(t, conn, wrapped)
}

// The warning has to reach the user at startup, i.e. off the config itself,
// not only when someone remembers to call the helper.
func TestClientConfigWarnsOnGecko(t *testing.T) {
	log, logs := observedLogger()
	restore := logger
	logger = log
	defer func() { logger = restore }()

	config := &clientConfig{Server: "example.com"}
	config.Obfs.Type = "gecko"
	config.Obfs.Gecko.Password = "g3ck0_in_the_wall"
	// Chrome parroting is on unless explicitly disabled, so both warnings fire.
	_, _ = config.Config()

	assert.Equal(t, 2, logs.FilterLevelExact(zapcore.WarnLevel).Len())
	assert.Equal(t, 1, logs.FilterMessageSnippet("parroting").Len())
}

// A share URI is the likeliest way a user ends up on gecko without having
// chosen it, so that path must warn just as loudly as an explicit config file.
func TestClientConfigWarnsOnGeckoFromURI(t *testing.T) {
	log, logs := observedLogger()
	restore := logger
	logger = log
	defer func() { logger = restore }()

	config := &clientConfig{Server: "chameleon://pw@geckotown.com:8443/?obfs=gecko&obfs-password=hidden"}
	_, _ = config.Config()

	assert.Equal(t, "gecko", config.Obfs.Type)
	assert.Equal(t, 2, logs.FilterLevelExact(zapcore.WarnLevel).Len())
	assert.Equal(t, 1, logs.FilterMessageSnippet("parroting").Len())
}

func TestClientConfigNoWarnWithoutGecko(t *testing.T) {
	log, logs := observedLogger()
	restore := logger
	logger = log
	defer func() { logger = restore }()

	config := &clientConfig{Server: "example.com"}
	config.Obfs.Type = "salamander"
	config.Obfs.Salamander.Password = "cry_me_a_r1ver"
	_, _ = config.Config()

	assert.Zero(t, logs.FilterLevelExact(zapcore.WarnLevel).Len())
}

func TestServerConfigWarnsOnGecko(t *testing.T) {
	log, logs := observedLogger()
	restore := logger
	logger = log
	defer func() { logger = restore }()

	config := &serverConfig{Listen: "127.0.0.1:0"}
	config.Obfs.Type = "gecko"
	config.Obfs.Gecko.Password = "g3ck0_in_the_wall"
	_, _ = config.Config()

	// The server cannot parrot Chrome, so it only gets the deprecation notice.
	assert.Equal(t, 1, logs.FilterLevelExact(zapcore.WarnLevel).Len())
	assert.Zero(t, logs.FilterMessageSnippet("parroting").Len())
}
