/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/rkcloudchain/cccsp/crypto"
	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var tempDir string

func TestMain(m *testing.M) {
	var err error
	tempDir, err = ioutil.TempDir("", "cccsp")
	if err != nil {
		fmt.Printf("Failed to create temporary directory: %s\n\n", err)
		os.Exit(-1)
	}
	defer os.RemoveAll(tempDir)

	ret := m.Run()
	os.Exit(ret)
}

func TestInvalidIdentifier(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.GetKey(nil)
	assert.Error(t, err)
	assert.Nil(t, k)

	k, err = csp.GetKey([]byte{0, 1, 2, 3, 4, 5, 6})
	assert.Error(t, err)
	assert.Nil(t, k)
}

func TestKeyGenerate(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.KeyGenerate("ECDSA384", false)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	assert.True(t, k.Private())

	ecdsaK, ok := k.(*key.ECDSAPrivateKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P384(), ecdsaK.Curve)
	assert.NotZero(t, ecdsaK.D.Cmp(big.NewInt(0)))

	kk, err := csp.KeyGenerate("RSA3072", true)
	assert.NoError(t, err)
	assert.NotNil(t, kk)
	assert.True(t, kk.Private())

	rsaK, ok := kk.(*key.RSAPrivateKey)
	assert.True(t, ok)
	assert.Equal(t, 3072, rsaK.PrivateKey.Size()*8)

	kkk, err := csp.KeyGenerate("AES24", false)
	assert.NoError(t, err)
	assert.NotNil(t, kkk)
	assert.True(t, kkk.Private())

	aesK, ok := kkk.(*key.AESPrivateKey)
	assert.True(t, ok)
	assert.Equal(t, 24, len(aesK.PrivateKey))
}

func TestKeyIdentifier(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.KeyGenerate("ECDSA256", false)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	id := k.Identifier()
	assert.NotZero(t, len(id))

	kk, err := csp.KeyGenerate("RSA2048", false)
	assert.NoError(t, err)
	assert.NotNil(t, kk)

	id2 := kk.Identifier()
	assert.NotZero(t, len(id2))

	kkk, err := csp.KeyGenerate("AES16", false)
	assert.NoError(t, err)
	assert.NotNil(t, kkk)

	id3 := kkk.Identifier()
	assert.NotZero(t, len(id3))
}

func TestGetKeyByIdentifier(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.KeyGenerate("ECDSA521", false)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	k2, err := csp.GetKey(k.Identifier())
	assert.NoError(t, err)
	assert.NotNil(t, k2)

	assert.True(t, k2.Private())
	assert.Equal(t, k.Identifier(), k2.Identifier())
}

func TestPublicKeyFromPrivateKey(t *testing.T) {
	csp, err := New(tempDir)
	assert.NoError(t, err)

	k, err := csp.KeyGenerate("RSA4096", false)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	pk, err := k.Public()
	assert.NoError(t, err)
	assert.NotNil(t, pk)

	assert.False(t, pk.Private())
}

func TestPublicKeyBytes(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.KeyGenerate("ECDSA521", false)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	pk, err := k.Public()
	assert.NoError(t, err)
	assert.NotNil(t, pk)

	raw, err := pk.Raw()
	assert.NoError(t, err)
	assert.NotZero(t, len(raw))

	id := pk.Identifier()
	assert.NotZero(t, len(id))
}

func TestHash(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.Hash([]byte(""), "abc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported hash family")

	msg := []byte("msg, family")
	h, err := csp.Hash(msg, "SHA3_384")
	assert.NoError(t, err)
	assert.Equal(t, 384, len(h)*8)
}

func TestEncryptAndDecrypt(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	ptext := []byte("Hello world")
	k, err := csp.KeyGenerate("RSA2048", true)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	encrypted, err := csp.Encrypt(k, ptext, &crypto.RSAOAEPOpts{Hash: sha3.New384()})
	assert.NoError(t, err)
	assert.NotNil(t, encrypted)

	decryped, err := csp.Decrypt(k, encrypted, &crypto.RSAOAEPOpts{Hash: sha3.New384()})
	assert.NoError(t, err)
	assert.NotNil(t, decryped)

	assert.Equal(t, ptext, decryped)
}

func TestSignAndVerify(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	ptext := []byte("bla bla bla")
	k, err := csp.KeyGenerate("ECDSA256", true)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	sigma, err := csp.Sign(k, ptext, nil)
	assert.NoError(t, err)
	assert.NotZero(t, len(sigma))

	valid, err := csp.Verify(k, sigma, ptext, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestGetHash(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	h, err := csp.GetHash("SHA384")
	assert.NoError(t, err)
	assert.Equal(t, sha512.New384(), h)

	_, err = csp.GetHash("abc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported hash algorithm")
}

func TestAESKeyStore(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.KeyGenerate("AES32", false)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	id := k.Identifier()
	assert.NotNil(t, id)

	k2, err := csp.GetKey(id)
	assert.NoError(t, err)
	assert.NotNil(t, k2)

	aesK1, ok := k.(*key.AESPrivateKey)
	assert.True(t, ok)
	aesK2, ok := k2.(*key.AESPrivateKey)
	assert.True(t, ok)

	assert.Equal(t, aesK1.PrivateKey, aesK2.PrivateKey)
}

func TestPublicKeyStore(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.KeyGenerate("RSA2048", false)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	pk, err := k.Public()
	assert.NoError(t, err)
	assert.NotNil(t, pk)

	raw, err := pk.Raw()
	assert.NoError(t, err)
	assert.NotNil(t, raw)

	_, err = csp.KeyImport(raw, "RSAPUBKEY", false)
	assert.NoError(t, err)

	id := pk.Identifier()
	assert.NotNil(t, id)

	k2, err := csp.GetKey(id)
	assert.NoError(t, err)
	assert.False(t, k2.Private())

	rsaK1, ok := pk.(*key.RSAPublicKey)
	assert.True(t, ok)
	rsaK2, ok := k2.(*key.RSAPublicKey)
	assert.True(t, ok)

	assert.Equal(t, rsaK1.Size(), rsaK2.Size())
	assert.Equal(t, rsaK1.N, rsaK2.N)
	assert.Equal(t, rsaK1.E, rsaK2.E)
}

func TestInvalidKeyGenerate(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.KeyGenerate("", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid algorithm, it must not be empty")

	_, err = csp.KeyGenerate("algorithm", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported algorithm")
}

func TestInvalidKeyImport(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.KeyImport(nil, "algorithm", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw, it must not be nil")

	_, err = csp.KeyImport([]byte{0}, "algorithm", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported key import algorithm")
}

func TestInvalidEncrypt(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.Encrypt(nil, []byte{0}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key, it must not be nil")

	ecdsaK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k, err := key.New(ecdsaK)
	require.NoError(t, err)

	_, err = csp.Encrypt(k, []byte{0}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported encryption options")

	rsaK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	k, err = key.New(rsaK)
	require.NoError(t, err)

	_, err = csp.Encrypt(k, []byte{0}, nil)
	assert.Error(t, err)
}

func TestInvalidDecrypt(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.Decrypt(nil, []byte{0}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key, it must not be nil")

	ecdsaK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k, err := key.New(ecdsaK)
	require.NoError(t, err)

	_, err = csp.Decrypt(k, []byte{0}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported encryption options")

	rsaK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	k, err = key.New(rsaK)
	require.NoError(t, err)

	_, err = csp.Decrypt(k, []byte{0}, nil)
	assert.Error(t, err)
}

func TestInvalidSign(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.Sign(nil, []byte{0}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key, must not be nil")

	k, err := key.New([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	require.NoError(t, err)

	_, err = csp.Sign(k, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid digest, cannot be empty")

	_, err = csp.Sign(k, []byte{0, 1, 2}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported key type")
}

func TestInvalidVerify(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.Verify(nil, []byte{0}, []byte{0}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key, must not be nil")

	k, err := key.New([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	require.NoError(t, err)

	_, err = csp.Verify(k, nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature, cannot be empty")

	_, err = csp.Verify(k, []byte{0}, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid digest, cannot be empty")

	_, err = csp.Verify(k, []byte{0, 1, 2}, []byte{0, 1, 2}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported key type")
}

func TestInvalidHash(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.Hash([]byte{0}, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid hash family. It must not be empty")

	_, err = csp.Hash([]byte{0}, "family")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported hash family")
}

func TestInvalidGetHash(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	_, err = csp.GetHash("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid algorithm, it must not be empty")

	_, err = csp.GetHash("algo")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported hash algorithm")
}
