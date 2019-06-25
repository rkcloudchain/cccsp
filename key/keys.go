/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"reflect"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"golang.org/x/crypto/sha3"
)

// New returns a cccsp Key instance
func New(privKey interface{}) (cccsp.Key, error) {
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		return &ECDSAPrivateKey{k}, nil
	case *rsa.PrivateKey:
		return &RSAPrivateKey{k}, nil
	case *ecdsa.PublicKey:
		return &ECDSAPublicKey{k}, nil
	case ecdsa.PublicKey:
		return &ECDSAPublicKey{&k}, nil
	case *rsa.PublicKey:
		return &RSAPublicKey{k}, nil
	case rsa.PublicKey:
		return &RSAPublicKey{&k}, nil
	case []byte:
		return &AESPrivateKey{k}, nil
	default:
		return nil, errors.Errorf("Unsupported private key type: %v", reflect.TypeOf(privKey))
	}
}

// AESPrivateKey contains a aes private key
type AESPrivateKey struct {
	PrivateKey []byte
}

// Raw converts this key to its byte representation.
func (k *AESPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}

// Identifier returns the identifier of this key
func (k *AESPrivateKey) Identifier() []byte {
	hash := sha3.New256()
	hash.Write([]byte{0x01})
	hash.Write(k.PrivateKey)
	return hash.Sum(nil)
}

// SKI is for compatibility with Hyperledger Fabric bccsp
func (k *AESPrivateKey) SKI() []byte {
	hash := sha256.New()
	hash.Write([]byte{0x01})
	hash.Write(k.PrivateKey)
	return hash.Sum(nil)
}

// Private returns true if this key is a private key.
// false otherwise
func (k *AESPrivateKey) Private() bool {
	return true
}

// Public returns the corresponding public key part of
// an asymmetric public/private key pair.
func (k *AESPrivateKey) Public() (cccsp.Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key")
}
