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

	encryptor := &rsaEncryptor{}
	encrypted, err := encryptor.Encrypt(pk, ptext, opts)
	assert.NoError(t, err)

	sk, err := key.New(rsaKey)
	require.NoError(t, err)

	decryptor := &rsaDecryptor{}
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

	encryptor := &rsaEncryptor{}
	encrypted, err := encryptor.Encrypt(pk, ptext, opts)
	assert.NoError(t, err)

	sk, err := key.New(rsaKey)
	require.NoError(t, err)

	decryptor := &rsaDecryptor{}
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
	opts := &RSAPKCS1v15Opts{}

	encryptor := &rsaEncryptor{}
	encrypted, err := encryptor.Encrypt(sk, ptext, opts)
	assert.NoError(t, err)

	decryptor := &rsaDecryptor{}
	decrypted, err := decryptor.Decrypt(sk, encrypted, opts)
	assert.NoError(t, err)
	assert.Equal(t, ptext, decrypted)
}

func TestRSADecryptWithPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk, err := key.New(rsaKey.PublicKey)
	require.NoError(t, err)

	opts := &RSAPKCS1v15Opts{}
	decryptor := &rsaDecryptor{}
	_, err = decryptor.Decrypt(pk, []byte("message"), opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key type")
}
