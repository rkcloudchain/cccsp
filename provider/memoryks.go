package provider

import (
	"encoding/hex"
	"sync"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
)

// NewMemoryKeyStore instantiates an ephemeral in-memory keystore
func NewMemoryKeyStore() cccsp.KeyStore {
	return &memoryKeyStore{
		keys: make(map[string]cccsp.Key),
	}
}

type memoryKeyStore struct {
	keys map[string]cccsp.Key
	m    sync.RWMutex
}

func (ks *memoryKeyStore) StoreKey(k cccsp.Key) error {
	if k == nil {
		return errors.New("Key is nil")
	}

	id := hex.EncodeToString(k.Identifier())

	ks.m.Lock()
	defer ks.m.Unlock()

	if _, found := ks.keys[id]; found {
		return errors.Errorf("ID %x already exists in the keystore", k.Identifier())
	}
	ks.keys[id] = k

	return nil
}

func (ks *memoryKeyStore) LoadKey(id []byte) (cccsp.Key, error) {
	if len(id) == 0 {
		return nil, errors.New("ID is nil or empty")
	}

	idStr := hex.EncodeToString(id)

	ks.m.RLock()
	defer ks.m.RUnlock()

	if key, found := ks.keys[idStr]; found {
		return key, nil
	}

	return nil, errors.Errorf("No key found for id: %x", id)
}
