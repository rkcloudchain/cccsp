package cccsp

import (
	"hash"
)

type hasher struct {
	hash func() hash.Hash
}

func (h *hasher) Hash(msg []byte) ([]byte, error) {
	hash := h.hash()
	if _, err := hash.Write(msg); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}
