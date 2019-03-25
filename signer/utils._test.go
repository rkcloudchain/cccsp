package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalECDSASignature(t *testing.T) {
	_, _, err := unmarshalECDSASignature(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed unmarshalling signature [")

	_, _, err = unmarshalECDSASignature([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed unmarshalling signature [")

	_, _, err = unmarshalECDSASignature([]byte{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed unmarshalling signature [")

	sigma, err := marshalECDSASignature(big.NewInt(-1), big.NewInt(1))
	assert.NoError(t, err)
	_, _, err = unmarshalECDSASignature(sigma)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature, R must be larger than zero")

	sigma, err = marshalECDSASignature(big.NewInt(0), big.NewInt(1))
	assert.NoError(t, err)
	_, _, err = unmarshalECDSASignature(sigma)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature, R must be larger than zero")

	sigma, err = marshalECDSASignature(big.NewInt(1), big.NewInt(0))
	assert.NoError(t, err)
	_, _, err = unmarshalECDSASignature(sigma)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature, S must be larger than zero")

	sigma, err = marshalECDSASignature(big.NewInt(1), big.NewInt(-1))
	assert.NoError(t, err)
	_, _, err = unmarshalECDSASignature(sigma)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature, S must be larger than zero")

	sigma, err = marshalECDSASignature(big.NewInt(1), big.NewInt(1))
	assert.NoError(t, err)
	r, s, err := unmarshalECDSASignature(sigma)
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(1), r)
	assert.Equal(t, big.NewInt(1), s)
}

func TestIsLowS(t *testing.T) {
	lowKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	lowS, err := isLowS(&lowKey.PublicKey, big.NewInt(0))
	assert.NoError(t, err)
	assert.True(t, lowS)

	s := new(big.Int)
	s = s.Set(curveHalfOrdersAt(elliptic.P256()))

	lowS, err = isLowS(&lowKey.PublicKey, s)
	assert.NoError(t, err)
	assert.True(t, lowS)

	s = s.Add(s, big.NewInt(1))
	lowS, err = isLowS(&lowKey.PublicKey, s)
	assert.NoError(t, err)
	assert.False(t, lowS)

	s, modified, err := toLowS(&lowKey.PublicKey, s)
	assert.NoError(t, err)
	assert.True(t, modified)

	lowS, err = isLowS(&lowKey.PublicKey, s)
	assert.NoError(t, err)
	assert.True(t, lowS)
}
