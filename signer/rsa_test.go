/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestRSASignerSign(t *testing.T) {
	signer := NewSigner(RSA)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kk, err := key.New(k)
	require.NoError(t, err)

	msg := []byte("bla bla message")
	_, err = signer.Sign(kk, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid options, must be different from nil")

	_, err = signer.Sign(kk, msg, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA3_256})
	assert.Error(t, err)

	hf := sha3.New256()
	hf.Write(msg)
	digest := hf.Sum(nil)
	sigma, err := signer.Sign(kk, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA3_256})
	assert.NoError(t, err)

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA3_256}
	err = rsa.VerifyPSS(&k.PublicKey, crypto.SHA3_256, msg, sigma, opts)
	assert.Error(t, err)

	err = rsa.VerifyPSS(&k.PublicKey, crypto.SHA3_256, digest, sigma, opts)
	assert.NoError(t, err)

	verifier := NewVerifier(RSA)
	_, err = verifier.Verify(kk, sigma, msg, opts)
	assert.Error(t, err)

	valid, err := verifier.Verify(kk, sigma, digest, opts)
	assert.NoError(t, err)
	assert.True(t, valid)
}

type hashFunc func() crypto.Hash

func (h hashFunc) HashFunc() crypto.Hash {
	return h()
}

func TestRSASignerSign_PKCS1v15(t *testing.T) {
	signer := NewSigner(RSA)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kk, err := key.New(k)
	require.NoError(t, err)

	msg := []byte("bla bla message")

	_, err = signer.Sign(kk, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid options, must be different from nil")

	_, err = signer.Sign(kk, msg, hashFunc(func() crypto.Hash { return crypto.SHA256 }))
	assert.Error(t, err)

	hf := sha256.New()
	hf.Write(msg)
	digest := hf.Sum(nil)
	sigma, err := signer.Sign(kk, digest, hashFunc(func() crypto.Hash { return crypto.SHA256 }))
	assert.NoError(t, err)

	verifier := NewVerifier(RSA)
	valid, err := verifier.Verify(kk, sigma, digest, hashFunc(func() crypto.Hash { return crypto.SHA256 }))
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestRSASignerWithPublicKey(t *testing.T) {
	rsaK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sk, err := key.New(rsaK)
	require.NoError(t, err)

	signer := NewSigner(RSA)
	msg := []byte("bla bla bla")
	hf := sha3.New256()
	hf.Write(msg)
	digest := hf.Sum(nil)

	_, err = signer.Sign(nil, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid options, must be different from nil")

	_, err = signer.Sign(nil, digest, &rsa.PSSOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key type, must be *key.RSAPrivateKey")

	sigma, err := signer.Sign(sk, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA3_256})
	assert.NoError(t, err)
	assert.NotNil(t, sigma)

	pk, err := key.New(rsaK.PublicKey)
	require.NoError(t, err)
	verifier := NewVerifier(RSA)
	_, err = verifier.Verify(nil, sigma, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid options, it must not be nil")

	_, err = verifier.Verify(nil, sigma, digest, &rsa.PSSOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key type, must be *key.RSAPrivateKey or *key.RSAPublicKey")

	valid, err := verifier.Verify(pk, sigma, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA3_256})
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestErrorSignerAlgorithm(t *testing.T) {
	assert.Panics(t, func() {
		NewSigner("bac")
	})
}

func TestErrorVerifierAlgorithm(t *testing.T) {
	assert.Panics(t, func() {
		NewVerifier("abc")
	})
}
