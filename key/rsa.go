package key

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
)

// RSAPrivateKey contains a rsa private key
type RSAPrivateKey struct {
	*rsa.PrivateKey
}

// Raw converts this key to its byte representation.
func (k *RSAPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}

// RSAPublicKey contains a rsa public key
type RSAPublicKey struct {
	*rsa.PublicKey
}

// Raw converts this key to its byte representation.
func (k *RSAPublicKey) Raw() ([]byte, error) {
	if k.PublicKey == nil {
		return nil, errors.New("Failed marshalling key, key is nil")
	}

	raw, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return nil, errors.Errorf("Failed marshalling key [%s]", err)
	}

	return raw, nil
}
