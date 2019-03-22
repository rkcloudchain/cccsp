/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hash

import (
	"hash"
)

// Hasher is a hash object
type Hasher struct {
	hash func() hash.Hash
}

// New creates a new Hasher
func New(hash func() hash.Hash) *Hasher {
	return &Hasher{hash: hash}
}

// Hash calculate the hash of the message
func (h *Hasher) Hash(msg []byte) ([]byte, error) {
	hash := h.hash()
	if _, err := hash.Write(msg); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

// GetHash returns the underlying hash.Hash interface
func (h *Hasher) GetHash() hash.Hash {
	return h.hash()
}
