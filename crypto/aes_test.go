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
	encryptor := &aescbcpkcs7Encryptor{}

	k, err := key.New(keyBytes)
	require.NoError(t, err)

	encrypted, err := encryptor.Encrypt(k, ptext, &AESCBCPKCS7Opts{PRNG: rand.Reader})
	assert.NoError(t, err)

	decryptor := &aescbcpkcs7Decryptor{}
	decrypted, err := decryptor.Decrypt(k, encrypted, &AESCBCPKCS7Opts{PRNG: rand.Reader})
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}

func TestAESEncryptAndDecryptWithIV(t *testing.T) {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	ivBytes := make([]byte, aes.BlockSize)
	rand.Read(ivBytes)

	var ptext = []byte("bla1 bla1")
	encryptor := &aescbcpkcs7Encryptor{}

	k, err := key.New(keyBytes)
	require.NoError(t, err)

	encrypted, err := encryptor.Encrypt(k, ptext, &AESCBCPKCS7Opts{IV: ivBytes})
	assert.NoError(t, err)

	decryptor := &aescbcpkcs7Decryptor{}
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
	encryptor := &aescbcpkcs7Encryptor{}

	k, err := key.New(keyBytes)
	require.NoError(t, err)

	_, err = encryptor.Encrypt(k, ptext, &AESCBCPKCS7Opts{IV: ivBytes})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid IV")
}
