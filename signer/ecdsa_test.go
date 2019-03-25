/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECDSASignerSign(t *testing.T) {
	signer := NewSigner(ECDSA)

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kk, err := key.New(k)
	require.NoError(t, err)

	msg := []byte("bla bla bla")
	sigma, err := signer.Sign(kk, msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sigma)

	verifier := NewVerifier(ECDSA)
	valid, err := verifier.Verify(kk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	pk, err := kk.Public()
	assert.NoError(t, err)
	valid, err = verifier.Verify(pk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestECDSAVerifierWithPublicKey(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	sk, err := key.New(k)
	require.NoError(t, err)

	signer := NewSigner(ECDSA)
	msg := []byte("hello world")
	sigma, err := signer.Sign(sk, msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sigma)

	pk, err := key.New(k.PublicKey)
	require.NoError(t, err)

	verifier := NewVerifier(ECDSA)
	valid, err := verifier.Verify(pk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestECDSASignerWithErrorKey(t *testing.T) {
	signer := NewSigner(ECDSA)
	msg := []byte("bla bla bla")
	_, err := signer.Sign(nil, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key type, must be *key.ECDSAPrivateKey")

	rsaK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	k, err := key.New(rsaK)
	require.NoError(t, err)

	_, err = signer.Sign(k, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key type, must be *key.ECDSAPrivateKey")
}
