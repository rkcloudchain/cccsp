package key

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// RSAPrivateKey contains a rsa private key
type RSAPrivateKey struct {
	*rsa.PrivateKey
}

type rsaPublicKeyASN struct {
	N *big.Int
	E int
}

// Raw converts this key to its byte representation.
func (k *RSAPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}

// Identifier returns the identifier of this key
func (k *RSAPrivateKey) Identifier() []byte {
	if k.PrivateKey == nil {
		return nil
	}

	raw, _ := asn1.Marshal(rsaPublicKeyASN{N: k.PrivateKey.N, E: k.PrivateKey.E})
	hash := sha3.New256()
	hash.Write(raw)
	return hash.Sum(nil)
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

// Identifier returns the identifier of this key
func (k *RSAPublicKey) Identifier() []byte {
	if k.PublicKey == nil {
		return nil
	}

	raw, _ := asn1.Marshal(rsaPublicKeyASN{N: k.PublicKey.N, E: k.PublicKey.E})
	hash := sha3.New256()
	hash.Write(raw)
	return hash.Sum(nil)
}
