/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func TestHash(t *testing.T) {
	h := NewHasher(sha3.New256)
	msg := []byte("Hello World")
	out, err := h.Hash(msg)
	assert.NoError(t, err)

	h2 := sha3.New256()
	h2.Write(msg)
	out2 := h2.Sum(nil)
	assert.Equal(t, out2, out)

	hf := h.GetHash()
	assert.Equal(t, sha3.New256(), hf)
}
