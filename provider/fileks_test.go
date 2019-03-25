package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvalidStoreKey(t *testing.T) {
	_, err := NewFileKEyStore("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "An invalid KeyStore path provided. Path cannot be an empty string")

	ks, err := NewFileKEyStore(tempDir)
	assert.NoError(t, err)

	err = ks.StoreKey(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key, it must be different from nil")
}

func TestInvalidLoadKey(t *testing.T) {
	ks, err := NewFileKEyStore(tempDir)
	assert.NoError(t, err)

	_, err = ks.LoadKey(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid identifier, cannot be of zero length")
}

func TestStoreLoadKey(t *testing.T) {
	ks, err := NewFileKEyStore(tempDir)
	assert.NoError(t, err)

	ecdsaK, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	k, err := key.New(ecdsaK.PublicKey)
	require.NoError(t, err)

	err = ks.StoreKey(k)
	assert.NoError(t, err)

	k1, err := ks.LoadKey(k.Identifier())
	assert.NoError(t, err)

	raw, err := k.Raw()
	assert.NoError(t, err)
	raw1, err := k1.Raw()
	assert.NoError(t, err)
	assert.Equal(t, raw, raw1)
}
