/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"testing"

	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESEncryptAndDecryptWithPRNG(t *testing.T) {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	var ptext = []byte("bla bla")
	encryptor := NewEncryptor(AES)

	k, err := key.New(keyBytes)
	require.NoError(t, err)

	encrypted, err := encryptor.Encrypt(k, ptext, &AESCBCPKCS7Opts{PRNG: rand.Reader})
	assert.NoError(t, err)

	decryptor := NewDecryptor(AES)
	decrypted, err := decryptor.Decrypt(k, encrypted, &AESCBCPKCS7Opts{PRNG: rand.Reader})
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}
func TestAESEncryptAndDecryptWithPRNG2(t *testing.T) {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	var ptext = []byte("bla bla")
	encryptor := NewEncryptor(AES)

	k, err := key.New(keyBytes)
	require.NoError(t, err)

	encrypted, err := encryptor.Encrypt(k, ptext, AESCBCPKCS7Opts{PRNG: rand.Reader})
	assert.NoError(t, err)

	decryptor := NewDecryptor(AES)
	decrypted, err := decryptor.Decrypt(k, encrypted, AESCBCPKCS7Opts{PRNG: rand.Reader})
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}

func TestAESEncryptAndDecryptWithIV(t *testing.T) {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	ivBytes := make([]byte, aes.BlockSize)
	rand.Read(ivBytes)

	var ptext = []byte("bla1 bla1")
	encryptor := NewEncryptor(AES)

	k, err := key.New(keyBytes)
	require.NoError(t, err)

	encrypted, err := encryptor.Encrypt(k, ptext, &AESCBCPKCS7Opts{IV: ivBytes})
	assert.NoError(t, err)

	decryptor := NewDecryptor(AES)
	decrypted, err := decryptor.Decrypt(k, encrypted, &AESCBCPKCS7Opts{IV: ivBytes})
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}

func TestAESEncryptWithWrongIV(t *testing.T) {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	ivBytes := make([]byte, 12)
	rand.Read(ivBytes)

	var ptext = []byte("bla bla bla")
	encryptor := NewEncryptor(AES)

	k, err := key.New(keyBytes)
	require.NoError(t, err)

	_, err = encryptor.Encrypt(k, ptext, &AESCBCPKCS7Opts{IV: ivBytes})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid IV")
}

func TestAESEncryptWithRandReader(t *testing.T) {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	encryptor := NewEncryptor(AES)
	k, err := key.New(keyBytes)
	require.NoError(t, err)

	var ptext = []byte("bla bla bla")
	encrypted, err := encryptor.Encrypt(k, ptext, &AESCBCPKCS7Opts{})
	assert.NoError(t, err)

	decryptor := NewDecryptor(AES)
	decrypted, err := decryptor.Decrypt(k, encrypted, &AESCBCPKCS7Opts{})
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}
