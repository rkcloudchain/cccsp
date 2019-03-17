/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
