package cccsp

import (
	"crypto/rsa"

	"github.com/pkg/errors"
)

type rsaPrivateKey struct {
	privKey *rsa.PrivateKey
}

func (k *rsaPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}
