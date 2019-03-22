/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keygen

import (
	"crypto/elliptic"
	"testing"

	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
)

func TestRSAKeyGen(t *testing.T) {
	kg := New(RSA2048)
	k, err := kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.RSAPrivateKey{}, k)

	rsaKey := k.(*key.RSAPrivateKey)
	assert.NotNil(t, rsaKey)
	assert.Equal(t, 2048, rsaKey.Size()*8)

	kg = New(RSA3072)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.RSAPrivateKey{}, k)

	rsaKey = k.(*key.RSAPrivateKey)
	assert.NotNil(t, rsaKey)
	assert.Equal(t, 3072, rsaKey.Size()*8)

	kg = New(RSA4096)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.RSAPrivateKey{}, k)

	rsaKey = k.(*key.RSAPrivateKey)
	assert.NotNil(t, rsaKey.PrivateKey)
	assert.Equal(t, 4096, rsaKey.PrivateKey.Size()*8)
}

func TestECDSAKeyGen(t *testing.T) {
	kg := New(ECDSA256)
	k, err := kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.ECDSAPrivateKey{}, k)

	ecdsaK := k.(*key.ECDSAPrivateKey)
	assert.NotNil(t, ecdsaK)
	assert.Equal(t, elliptic.P256(), ecdsaK.Curve)

	kg = New(ECDSA384)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.ECDSAPrivateKey{}, k)

	ecdsaK = k.(*key.ECDSAPrivateKey)
	assert.NotNil(t, ecdsaK)
	assert.Equal(t, elliptic.P384(), ecdsaK.Curve)

	kg = New(ECDSA521)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.ECDSAPrivateKey{}, k)

	ecdsaK = k.(*key.ECDSAPrivateKey)
	assert.NotNil(t, ecdsaK.PrivateKey)
	assert.Equal(t, elliptic.P521(), ecdsaK.Curve)
}

func TestAESKeyGen(t *testing.T) {
	kg := New(AES16)
	k, err := kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.AESPrivateKey{}, k)

	aesK := k.(*key.AESPrivateKey)
	assert.NotNil(t, aesK.PrivateKey)
	assert.Equal(t, 16, len(aesK.PrivateKey))

	kg = New(AES24)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.AESPrivateKey{}, k)

	aesK = k.(*key.AESPrivateKey)
	assert.NotNil(t, aesK.PrivateKey)
	assert.Equal(t, 24, len(aesK.PrivateKey))

	kg = New(AES32)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.AESPrivateKey{}, k)

	aesK = k.(*key.AESPrivateKey)
	assert.NotNil(t, aesK.PrivateKey)
	assert.Equal(t, 32, len(aesK.PrivateKey))
}

func TestErrorAlgorithm(t *testing.T) {
	assert.Panics(t, func() {
		New("abc")
	})
}
