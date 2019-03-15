package key

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/pkg/errors"
)

// ECDSAPrivateKey contains a ecdsa private key
type ECDSAPrivateKey struct {
	*ecdsa.PrivateKey
}

// Raw converts this key to its byte representation.
func (k *ECDSAPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}

// ECDSAPublicKey contains a ecdsa public key
type ECDSAPublicKey struct {
	*ecdsa.PublicKey
}

// Raw converts this key to its byte representation.
func (k *ECDSAPublicKey) Raw() ([]byte, error) {
	if k.PublicKey == nil {
		return nil, errors.New("Failed marshalling key, key is nil")
	}

	raw, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed marshalling key")
	}
	return raw, nil
}


