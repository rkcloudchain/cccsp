/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package importer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func TestErrorKeyImportAlgorithm(t *testing.T) {
	assert.Panics(t, func() {
		New("abc")
	})
}

var ecCert = `-----BEGIN CERTIFICATE-----
MIICYjCCAgmgAwIBAgIUB3CTDOU47sUC5K4kn/Caqnh114YwCgYIKoZIzj0EAwIw
fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMTYxMDEyMTkzMTAw
WhcNMjExMDExMTkzMTAwWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZv
cm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEfMB0GA1UEChMWSW50ZXJuZXQg
V2lkZ2V0cywgSW5jLjEMMAoGA1UECxMDV1dXMRQwEgYDVQQDEwtleGFtcGxlLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKIH5b2JaSmqiQXHyqC+cmknICcF
i5AddVjsQizDV6uZ4v6s+PWiJyzfA/rTtMvYAPq/yeEHpBUB1j053mxnpMujYzBh
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQXZ0I9
qp6CP8TFHZ9bw5nRtZxIEDAfBgNVHSMEGDAWgBQXZ0I9qp6CP8TFHZ9bw5nRtZxI
EDAKBggqhkjOPQQDAgNHADBEAiAHp5Rbp9Em1G/UmKn8WsCbqDfWecVbZPQj3RK4
oG5kQQIgQAe4OOKYhJdh3f7URaKfGTf492/nmRmtK+ySKjpHSrU=
-----END CERTIFICATE-----
`

func TestECDSACertImport(t *testing.T) {
	block, _ := pem.Decode([]byte(ecCert))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	ki := New(X509CERT)
	k, err := ki.KeyImport(cert)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	assert.False(t, k.Private())
}

var rsaCert = `-----BEGIN CERTIFICATE-----
MIIDyzCCArOgAwIBAgIUGCc2sy++Qm+L++WKs8NjlIldBK4wDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DVNhbiBGcmFuY2lzY28xEzARBgNVBAoTCkNsb3VkRmxhcmUxHDAaBgNVBAsTE1N5
c3RlbXMgRW5naW5lZXJpbmcwHhcNMTYxMDI1MTQ0NjAwWhcNMjExMDI0MTQ0NjAw
WjBtMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzETMBEGA1UEChMKQ2xvdWRGbGFyZTEcMBoGA1UECxMTU3lz
dGVtcyBFbmdpbmVlcmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANX81ia5RIGzBQjkyMqZQLGPUQfDEkAIQc32eeXoPahYlOZNVhkILz3cidopxS31
maihOAslOAzJQIt/8mKA7DPrl6JvB2QZkfY7RwFwUm5zzeaqz3c4Z9j+BOrrOQ7H
CEIKqi22lUozORdiwaJdql1VWkoyt8fNgycfOREf+OUgQtSDyBVLLrON83HJPn2R
sXAj2HFDd+TdR3n/KqOIFUe6K9UcviN8Cx0CON5sQtkKViefRAqu97SPgwExQcgQ
8SrInuhBVzwrH5EhF8VQBe0R30x5SKIS2zDEWhh8x0QazGnbUg7Jm97RCx5fGSvm
RQVGljPbhg4bnJ72ipzbGpECAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1Ud
EwEB/wQFMAMBAf8wHQYDVR0OBBYEFDR4HwiWIf8GoNhIu+6i9JNjyBlIMB8GA1Ud
IwQYMBaAFDR4HwiWIf8GoNhIu+6i9JNjyBlIMA0GCSqGSIb3DQEBCwUAA4IBAQCl
ma+kzStsuJyqmp7bAsM/AH7s5YF2YB4hnXQLab0eV3cv7WqI2mJFuFO+7rdCgFhI
EwVOkjvj0J52LU2+sFy/r7VS/j4GOqEnKBBULeOhA8hp/v7PyJRkdzHqVJUlVVPD
1wThW+eVh4OzQo46rxL3skBmGXkChUTaTpnMhiipBLxRkyNj8W5NrL1DR4/zxDRb
NG9dn2TThYpCE44Vav/9GxEYMzHSiXIqLYTjT5ohZ11EqLoQFEp7E0oZ8aTYQ3yF
3T7AdtaL6dcl3RV4cyKidRjhdyKCXKW3E50nSB0Gpg6cfqlQ/OpOScs4FOerqy/W
5dMGKIX/2l7rbzLQIqUK
-----END CERTIFICATE-----
`

func TestRSACertImport(t *testing.T) {
	block, _ := pem.Decode([]byte(rsaCert))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	ki := New(X509CERT)
	k, err := ki.KeyImport(cert)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	assert.False(t, k.Private())
}
