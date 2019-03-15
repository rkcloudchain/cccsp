package cccsp

import (
	"crypto/ecdsa"

	"github.com/pkg/errors"
)

type ecdsaPrivateKey struct {
	privKey *ecdsa.PrivateKey
}

func (k *ecdsaPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}
