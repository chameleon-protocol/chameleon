package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/core/v2/client"
)

// The seed has to come out identical on both ends from the same obfuscation
// password, since there is nothing on the wire to negotiate it with.
func TestPaddingSeedAgreesAcrossEnds(t *testing.T) {
	client := &clientConfig{Obfs: clientConfigObfs{
		Type:         "salamander-v2",
		SalamanderV2: clientConfigObfsSalamanderV2{Password: "shared_password", Realm: "example.com"},
	}}
	server := &serverConfig{Obfs: serverConfigObfs{
		Type:         "salamander-v2",
		SalamanderV2: serverConfigObfsSalamanderV2{Password: "shared_password", Realm: "example.com"},
	}}

	clientSeed, err := paddingSeed(client.obfsPassword(), client.Obfs.SalamanderV2.Realm)
	require.NoError(t, err)
	serverSeed, err := paddingSeed(server.obfsPassword(), server.Obfs.SalamanderV2.Realm)
	require.NoError(t, err)

	assert.Equal(t, clientSeed, serverSeed, "the two ends derived different padding seeds")
	assert.Len(t, clientSeed, paddingSeedLen)
}

// Different deployments must not share a padding length distribution -- that
// distribution being identical everywhere is the thing this replaces.
func TestPaddingSeedDiffersPerDeployment(t *testing.T) {
	a, err := paddingSeed("password_one", "")
	require.NoError(t, err)
	b, err := paddingSeed("password_two", "")
	require.NoError(t, err)
	c, err := paddingSeed("password_one", "other.realm")
	require.NoError(t, err)

	assert.False(t, bytes.Equal(a, b), "different passwords produced the same seed")
	assert.False(t, bytes.Equal(a, c), "different realms produced the same seed")
}

// Whichever obfuscator is configured, its password is the one that seeds
// padding; with obfuscation off there is no deployment secret to use.
func TestObfsPasswordSelection(t *testing.T) {
	tests := []struct {
		obfsType string
		want     string
	}{
		{"salamander", "v1_password"},
		{"salamander-v2", "v2_password"},
		{"gecko", "gecko_password"},
		{"plain", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.obfsType, func(t *testing.T) {
			c := &clientConfig{Obfs: clientConfigObfs{
				Type:         tt.obfsType,
				Salamander:   clientConfigObfsSalamander{Password: "v1_password"},
				SalamanderV2: clientConfigObfsSalamanderV2{Password: "v2_password"},
				Gecko:        clientConfigObfsGecko{Password: "gecko_password"},
			}}
			assert.Equal(t, tt.want, c.obfsPassword())

			s := &serverConfig{Obfs: serverConfigObfs{
				Type:         tt.obfsType,
				Salamander:   serverConfigObfsSalamander{Password: "v1_password"},
				SalamanderV2: serverConfigObfsSalamanderV2{Password: "v2_password"},
				Gecko:        serverConfigObfsGecko{Password: "gecko_password"},
			}}
			assert.Equal(t, tt.want, s.obfsPassword())
		})
	}
}

// Without obfuscation there is nothing to derive from, and the padding keeps
// the fixed ranges rather than getting a seed of zero bytes.
func TestNoPaddingSeedWithoutObfs(t *testing.T) {
	c := &clientConfig{Obfs: clientConfigObfs{Type: "plain"}}
	hyConfig := &client.Config{}
	require.NoError(t, c.fillPaddingSeed(hyConfig))
	assert.Nil(t, hyConfig.PaddingSeed)

	c.Obfs = clientConfigObfs{
		Type:         "salamander-v2",
		SalamanderV2: clientConfigObfsSalamanderV2{Password: "a_password"},
	}
	require.NoError(t, c.fillPaddingSeed(hyConfig))
	assert.Len(t, hyConfig.PaddingSeed, paddingSeedLen)
}
