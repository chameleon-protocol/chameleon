package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/core/v2/server"
)

func TestRealmPunchMaskRequiresObfs(t *testing.T) {
	for _, obfsType := range []string{"", "plain", "PLAIN"} {
		_, err := realmPunchMask(obfsType, "", "", "", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, errRealmPunchNeedsObfs)
		var cfgErr configError
		require.ErrorAs(t, err, &cfgErr)
		assert.Equal(t, "obfs.type", cfgErr.Field)
	}
}

func TestRealmPunchMaskPerObfsType(t *testing.T) {
	salamander, err := realmPunchMask("salamander", "v1-password", "", "", "")
	require.NoError(t, err)
	v2, err := realmPunchMask("salamander-v2", "", "v2-password", "deployment", "")
	require.NoError(t, err)
	gecko, err := realmPunchMask("gecko", "", "", "", "gecko-password")
	require.NoError(t, err)
	assert.NotEqual(t, salamander, v2)
	assert.NotEqual(t, v2, gecko)

	// The realm scopes the derivation, so the same v2 password in two
	// deployments must not produce one mask key.
	other, err := realmPunchMask("salamander-v2", "", "v2-password", "other-deployment", "")
	require.NoError(t, err)
	assert.NotEqual(t, v2, other)

	_, err = realmPunchMask("salamander-v2", "", "abc", "", "")
	require.Error(t, err)
	var cfgErr configError
	require.ErrorAs(t, err, &cfgErr)
	assert.Equal(t, "obfs.salamanderV2.password", cfgErr.Field)

	_, err = realmPunchMask("nonsense", "", "", "", "")
	require.Error(t, err)
	require.ErrorAs(t, err, &cfgErr)
	assert.Equal(t, "obfs.type", cfgErr.Field)
}

// Both ends must refuse to start, not fall back to punching in the clear.
// These go through the real startup path, which reaches the mask before it
// opens a socket.
func TestRealmStartupFailsWithoutObfs(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		addr, ok, err := parseServerRealmAddr("realm://token@example.com/realm")
		require.NoError(t, err)
		require.True(t, ok)
		c := &serverConfig{Listen: "realm://token@example.com/realm"}
		err = c.fillRealmConn(&server.Config{}, addr)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRealmPunchNeedsObfs)
	})
	t.Run("client", func(t *testing.T) {
		c := &clientConfig{
			Server: "realm://token@example.com/realm",
			Auth:   "password",
		}
		c.TLS.Insecure = true
		addr, ok, err := c.parseRealmAddr()
		require.NoError(t, err)
		require.True(t, ok)
		_, err = c.realmConfig(addr)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRealmPunchNeedsObfs)
	})
}
