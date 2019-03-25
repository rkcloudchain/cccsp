/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.KeyGenerate("ECDSA384", true)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	s, err := NewSigner(csp, k)
	assert.NoError(t, err)

	pk := s.Public()
	assert.NotNil(t, pk)

	digest := []byte("bla bla bla")
	sigma, err := s.Sign(rand.Reader, digest, nil)
	assert.NoError(t, err)
	assert.NotZero(t, len(sigma))
}

func TestSignerWithErrorParameter(t *testing.T) {
	_, err := NewSigner(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cccsp instance must be different from nil")

	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = NewSigner(csp, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key must be different from nil")

	aesK, err := key.New([]byte{0})
	require.NoError(t, err)
	_, err = NewSigner(csp, aesK)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed getting public key")

	rsaK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	k, err := key.New(rsaK.PublicKey)
	require.NoError(t, err)

	signer, err := NewSigner(csp, k)
	assert.NoError(t, err)

	_, err = signer.Sign(rand.Reader, []byte{0}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported key type")
}
