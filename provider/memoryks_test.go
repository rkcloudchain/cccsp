/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/rkcloudchain/cccsp/key"
	"github.com/stretchr/testify/assert"
)

func TestInvalidStore(t *testing.T) {
	ks := NewMemoryKeyStore()
	err := ks.StoreKey(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Key is nil")
}

func TestInvalidLoad(t *testing.T) {
	ks := NewMemoryKeyStore()
	_, err := ks.LoadKey(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ID is nil or empty")
}

func TestNoKeyFound(t *testing.T) {
	ks := NewMemoryKeyStore()
	id := []byte("foo")
	_, err := ks.LoadKey(id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No key found for id")
}

func TestStoreLoad(t *testing.T) {
	ks := NewMemoryKeyStore()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	cspKey, err := key.New(privKey)
	assert.NoError(t, err)

	err = ks.StoreKey(cspKey)
	assert.NoError(t, err)

	key, err := ks.LoadKey(cspKey.Identifier())
	assert.NoError(t, err)
	assert.Equal(t, cspKey, key)
}

func TestStoreExisting(t *testing.T) {
	ks := NewMemoryKeyStore()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	cspKey, err := key.New(privKey)
	assert.NoError(t, err)

	err = ks.StoreKey(cspKey)
	assert.NoError(t, err)

	err = ks.StoreKey(cspKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists in the keystore")
}
