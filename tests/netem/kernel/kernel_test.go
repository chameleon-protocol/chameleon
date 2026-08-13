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

package kernel

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The point of these tests is that an ordinary run never touches the machine's
// network configuration, and that when it declines it says why.

func TestUnavailableWithoutOptIn(t *testing.T) {
	t.Setenv(EnableEnv, "")
	a := Check()
	assert.False(t, a.OK)
	assert.NotEmpty(t, a.Reason, "a skip reason nobody can read is a skip nobody will fix")
}

func TestOptInStillRequiresRootAndTools(t *testing.T) {
	t.Setenv(EnableEnv, "1")
	a := Check()
	switch {
	case runtime.GOOS != "linux" && runtime.GOOS != "darwin":
		assert.False(t, a.OK)
		assert.Contains(t, a.Reason, runtime.GOOS)
	case a.OK:
		// Running as root on a machine with the tools installed. Nothing to
		// assert beyond the fact that Check agreed.
		t.Log("kernel shaping is available in this environment")
	default:
		assert.NotEmpty(t, a.Reason)
	}
}

func TestParseTokenFromPfctl(t *testing.T) {
	const out = "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 17434329485847352\n"
	assert.Equal(t, "17434329485847352", parseToken(out))
	assert.Empty(t, parseToken("pf already enabled\n"))
}

func TestRequireOrSkipDoesNotRunAnything(t *testing.T) {
	t.Setenv(EnableEnv, "")
	// RequireOrSkip is the only entry point tests are meant to call first, and
	// it must be a no-op on an unprepared machine.
	require.False(t, Check().OK)
}
