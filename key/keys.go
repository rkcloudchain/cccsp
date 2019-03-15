package key

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"reflect"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
)

// New returns a cccsp Key instance
func New(privKey interface{}) (cccsp.Key, error) {
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		return &ECDSAPrivateKey{k}, nil
	case *rsa.PrivateKey:
		return &RSAPrivateKey{k}, nil
	case []byte:
		return &AESPrivateKey{k}, nil
	default:
		return nil, errors.Errorf("Unsupported private key type: %v", reflect.TypeOf(privKey))
	}
}

// AESPrivateKey contains a aes private key
type AESPrivateKey struct {
	privKey []byte
}

// Raw converts this key to its byte representation.
func (k *AESPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}

// PrivateKey returns the aes private key
func (k *AESPrivateKey) PrivateKey() []byte {
	return k.privKey
}
