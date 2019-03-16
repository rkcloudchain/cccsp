package importer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAES256KeyImporter(t *testing.T) {
	ki := New(AES256)

	_, err := ki.KeyImport("Hello world")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice")

	_, err = ki.KeyImport(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice")

	_, err = ki.KeyImport([]byte(nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, it must not be nil")

	_, err = ki.KeyImport([]byte{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid key length")
}

func TestHMACKeyImporter(t *testing.T) {
	ki := New(HMAC)

	_, err := ki.KeyImport("Hello world")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice")

	_, err = ki.KeyImport(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice")

	_, err = ki.KeyImport([]byte(nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, it must not be nil")
}

func TestECDSAPublicKeyImporter(t *testing.T) {
	ki := New(ECDSAPUBKEY)

	_, err := ki.KeyImport("Hello world")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice or *ecdsa.PublicKey")

	_, err = ki.KeyImport(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice or *ecdsa.PublicKey")

	_, err = ki.KeyImport([]byte(nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, it must not be nil")

	_, err = ki.KeyImport([]byte{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to ECDSA public key")

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	raw, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)

	_, err = ki.KeyImport(raw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed casting to ECDSA public key, invalid raw material")
}

func TestECDSAPrivateKeyImporter(t *testing.T) {
	ki := New(ECDSAPRIKEY)

	_, err := ki.KeyImport("Hello world")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice or *ecdsa.PrivateKey")

	_, err = ki.KeyImport(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice or *ecdsa.PrivateKey")

	_, err = ki.KeyImport([]byte(nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, it must not be nil")

	_, err = ki.KeyImport([]byte{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to ECDSA private key")

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	raw := x509.MarshalPKCS1PrivateKey(k)

	_, err = ki.KeyImport(raw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed casting to ECDSA private key, invalid raw material")
}

func TestRSAPublicKeyImporter(t *testing.T) {
	ki := New(RSAPUBKEY)

	_, err := ki.KeyImport("Hello world")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice or *rsa.PublicKey")

	_, err = ki.KeyImport(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice or *rsa.PublicKey")

	_, err = ki.KeyImport([]byte(nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, it must not be nil")

	_, err = ki.KeyImport([]byte{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to RSA public key")

	k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	raw, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)

	_, err = ki.KeyImport(raw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed casting to RSA public key, invalid raw material")
}

func TestRSAPrivateKeyImporter(t *testing.T) {
	ki := New(RSAPRIKEY)

	_, err := ki.KeyImport("Hello world")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice or *rsa.PrivateKey")

	_, err = ki.KeyImport(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected byte slice or *rsa.PrivateKey")

	_, err = ki.KeyImport([]byte(nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, it must not be nil")

	_, err = ki.KeyImport([]byte{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to RSA private key")

	k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	raw, err := x509.MarshalECPrivateKey(k)
	require.NoError(t, err)

	_, err = ki.KeyImport(raw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed casting to RSA private key, invalid raw material")
}

func TestX509CertificateKeyImporter(t *testing.T) {
	ki := New(X509CERT)

	_, err := ki.KeyImport("Hello world")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected *x509.Certificate")

	_, err = ki.KeyImport(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material, expected *x509.Certificate")

	cert := &x509.Certificate{}
	cert.PublicKey = []byte("bla bla")

	_, err = ki.KeyImport(cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
}
