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
	kg := NewKeyGenerator(RSA2048)
	k, err := kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.RSAPrivateKey{}, k)

	rsaKey := k.(*key.RSAPrivateKey)
	assert.NotNil(t, rsaKey)
	assert.Equal(t, 2048, rsaKey.Size()*8)

	kg = NewKeyGenerator(RSA3072)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.RSAPrivateKey{}, k)

	rsaKey = k.(*key.RSAPrivateKey)
	assert.NotNil(t, rsaKey)
	assert.Equal(t, 3072, rsaKey.Size()*8)

	kg = NewKeyGenerator(RSA4096)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.RSAPrivateKey{}, k)

	rsaKey = k.(*key.RSAPrivateKey)
	assert.NotNil(t, rsaKey.PrivateKey)
	assert.Equal(t, 4096, rsaKey.PrivateKey.Size()*8)
}

func TestECDSAKeyGen(t *testing.T) {
	kg := NewKeyGenerator(ECDSA256)
	k, err := kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.ECDSAPrivateKey{}, k)

	ecdsaK := k.(*key.ECDSAPrivateKey)
	assert.NotNil(t, ecdsaK)
	assert.Equal(t, elliptic.P256(), ecdsaK.Curve)

	kg = NewKeyGenerator(ECDSA384)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.ECDSAPrivateKey{}, k)

	ecdsaK = k.(*key.ECDSAPrivateKey)
	assert.NotNil(t, ecdsaK)
	assert.Equal(t, elliptic.P384(), ecdsaK.Curve)

	kg = NewKeyGenerator(ECDSA521)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.ECDSAPrivateKey{}, k)

	ecdsaK = k.(*key.ECDSAPrivateKey)
	assert.NotNil(t, ecdsaK.PrivateKey)
	assert.Equal(t, elliptic.P521(), ecdsaK.Curve)
}

func TestAESKeyGen(t *testing.T) {
	kg := NewKeyGenerator(AES16)
	k, err := kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.AESPrivateKey{}, k)

	aesK := k.(*key.AESPrivateKey)
	assert.NotNil(t, aesK.PrivateKey)
	assert.Equal(t, 16, len(aesK.PrivateKey))

	kg = NewKeyGenerator(AES24)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.AESPrivateKey{}, k)

	aesK = k.(*key.AESPrivateKey)
	assert.NotNil(t, aesK.PrivateKey)
	assert.Equal(t, 24, len(aesK.PrivateKey))

	kg = NewKeyGenerator(AES32)
	k, err = kg.KeyGenerate()
	assert.NoError(t, err)
	assert.True(t, k.Private())
	assert.IsType(t, &key.AESPrivateKey{}, k)

	aesK = k.(*key.AESPrivateKey)
	assert.NotNil(t, aesK.PrivateKey)
	assert.Equal(t, 32, len(aesK.PrivateKey))
}
