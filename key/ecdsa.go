package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// ECDSAPrivateKey contains a ecdsa private key
type ECDSAPrivateKey struct {
	*ecdsa.PrivateKey
}

// Raw converts this key to its byte representation.
func (k *ECDSAPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}

// Identifier returns the identifier of this key
func (k *ECDSAPrivateKey) Identifier() []byte {
	if k.PrivateKey == nil {
		return nil
	}

	raw := elliptic.Marshal(k.Curve, k.PublicKey.X, k.PublicKey.Y)
	hash := sha3.New256()
	hash.Write(raw)
	return hash.Sum(nil)
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

// Identifier returns the identifier of this key
func (k *ECDSAPublicKey) Identifier() []byte {
	if k.PublicKey == nil {
		return nil
	}

	raw := elliptic.Marshal(k.PublicKey.Curve, k.PublicKey.X, k.PublicKey.Y)
	hash := sha3.New256()
	hash.Write(raw)
	return hash.Sum(nil)
}
