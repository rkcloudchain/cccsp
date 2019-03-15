package cccsp

import "github.com/pkg/errors"

type aesPrivateKey struct {
	privKey    []byte
	exportable bool
}

func (k *aesPrivateKey) Raw() ([]byte, error) {
	if k.exportable {
		return k.privKey, nil
	}
	return nil, errors.New("Not supported")
}
