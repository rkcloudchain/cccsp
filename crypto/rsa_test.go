/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestRSAEncryptAndDecrypt_OAEP(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk, err := key.New(rsaKey.PublicKey)
	require.NoError(t, err)

	ptext := []byte("bla bla message")
	opts := &RSAOAEPOpts{Hash: sha3.New256()}

	encryptor := NewEncryptor(RSA)
	encrypted, err := encryptor.Encrypt(pk, ptext, opts)
	assert.NoError(t, err)

	sk, err := key.New(rsaKey)
	require.NoError(t, err)

	decryptor := NewDecryptor(RSA)
	decrypted, err := decryptor.Decrypt(sk, encrypted, opts)
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}

func TestRSAEncryptAndDecrypt_OAEP2(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk, err := key.New(rsaKey.PublicKey)
	require.NoError(t, err)

	ptext := []byte("bla bla message")
	opts := RSAOAEPOpts{Hash: sha3.New512()}

	encryptor := NewEncryptor(RSA)
	encrypted, err := encryptor.Encrypt(pk, ptext, opts)
	assert.NoError(t, err)

	sk, err := key.New(rsaKey)
	require.NoError(t, err)

	decryptor := NewDecryptor(RSA)
	decrypted, err := decryptor.Decrypt(sk, encrypted, opts)
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}

func TestRSAEncryptAndDecrypt_PKCS1v15(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk, err := key.New(rsaKey.PublicKey)
	require.NoError(t, err)

	ptext := []byte("bla bla message")
	opts := &RSAPKCS1v15Opts{}

	encryptor := NewEncryptor(RSA)
	encrypted, err := encryptor.Encrypt(pk, ptext, opts)
	assert.NoError(t, err)

	sk, err := key.New(rsaKey)
	require.NoError(t, err)

	decryptor := NewDecryptor(RSA)
	decrypted, err := decryptor.Decrypt(sk, encrypted, opts)
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}

func TestRSAEncryptAndDecryptWithPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	sk, err := key.New(rsaKey)
	require.NoError(t, err)

	ptext := []byte("bla bla message")
	opts := RSAPKCS1v15Opts{}

	encryptor := NewEncryptor(RSA)
	encrypted, err := encryptor.Encrypt(sk, ptext, opts)
	assert.NoError(t, err)

	decryptor := NewDecryptor(RSA)
	decrypted, err := decryptor.Decrypt(sk, encrypted, opts)
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}

func TestRSADecryptWithPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk, err := key.New(rsaKey.PublicKey)
	require.NoError(t, err)

	opts := RSAPKCS1v15Opts{}
	decryptor := NewDecryptor(RSA)
	_, err = decryptor.Decrypt(pk, []byte("message"), opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key type")
}

func TestErrorEncryptAlgorithm(t *testing.T) {
	assert.Panics(t, func() {
		NewEncryptor("abc")
	})
}

func TestErrorDecryptAlgorithm(t *testing.T) {
	assert.Panics(t, func() {
		NewDecryptor("abc")
	})
}
