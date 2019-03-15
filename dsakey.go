package cccsp

import (
	"crypto/dsa"

	"github.com/pkg/errors"
)

type dsaPrivateKey struct {
	privKey *dsa.PrivateKey
}

func (k *dsaPrivateKey) Raw() ([]byte, error) {
	return nil, errors.New("Not supported")
}
