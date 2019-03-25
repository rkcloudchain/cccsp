/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/key"
	"github.com/rkcloudchain/cccsp/util"
)

// NewFileKEyStore instantiated a file-based key store at a given position
func NewFileKEyStore(path string) (cccsp.KeyStore, error) {
	ks := &fileKeyStore{path: path}
	return ks, ks.initialize()
}

type fileKeyStore struct {
	path   string
	isOpen bool
	m      sync.Mutex
}

func (ks *fileKeyStore) LoadKey(id []byte) (cccsp.Key, error) {
	if len(id) == 0 {
		return nil, errors.New("Invalid identifier, cannot be of zero length")
	}

	suffix := ks.getSuffix(hex.EncodeToString(id))
	switch suffix {
	case "key":
		k, err := ks.loadKey(hex.EncodeToString(id))
		if err != nil {
			return nil, errors.Errorf("Failed loading key [%x] [%s]", id, err)
		}
		return key.New(k)

	case "sk":
		k, err := ks.loadPrivateKey(hex.EncodeToString(id))
		if err != nil {
			return nil, err
		}

		switch k.(type) {
		case *ecdsa.PrivateKey, *rsa.PrivateKey:
			return key.New(k)
		default:
			return nil, errors.New("Private key type not recognized")
		}

	case "pk":
		k, err := ks.loadPublicKey(hex.EncodeToString(id))
		if err != nil {
			return nil, errors.Errorf("Failed loading public key [%x] [%s]", id, err)
		}

		switch k.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey:
			return key.New(k)
		default:
			return nil, errors.New("Public key type not recognized")
		}
	default:
		return nil, errors.Errorf("Key with identifier %s not found in %s", hex.EncodeToString(id), ks.path)
	}
}

func (ks *fileKeyStore) StoreKey(k cccsp.Key) (err error) {
	if k == nil {
		return errors.New("Invalid key, it must be different from nil")
	}

	switch kk := k.(type) {
	case *key.ECDSAPrivateKey:
		err = ks.storePrivateKey(hex.EncodeToString(k.Identifier()), kk.PrivateKey)
		if err != nil {
			return errors.Errorf("Failed storing ECDSA private key [%s]", err)
		}

	case *key.ECDSAPublicKey:
		err = ks.storePublicKey(hex.EncodeToString(k.Identifier()), kk.PublicKey)
		if err != nil {
			return errors.Errorf("Failed storing ECDSA public key [%s]", err)
		}

	case *key.RSAPrivateKey:
		err = ks.storePrivateKey(hex.EncodeToString(k.Identifier()), kk.PrivateKey)
		if err != nil {
			return errors.Errorf("Failed storing RSA private key [%s]", err)
		}

	case *key.RSAPublicKey:
		err = ks.storePublicKey(hex.EncodeToString(k.Identifier()), kk.PublicKey)
		if err != nil {
			return errors.Errorf("Failed storing RSA public key [%s]", err)
		}

	case *key.AESPrivateKey:
		err = ks.storeKey(hex.EncodeToString(k.Identifier()), kk.PrivateKey)
		if err != nil {
			return errors.Errorf("Failed storing AES key [%s]", err)
		}

	default:
		return errors.Errorf("Key type not reconigned [%s]", k)
	}

	return
}

func (ks *fileKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "pk")
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return util.PEMToPublicKey(raw)
}

func (ks *fileKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "sk")
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return util.PEMToPrivateKey(raw)
}

func (ks *fileKeyStore) loadKey(alias string) ([]byte, error) {
	path := ks.getPathForAlias(alias, "key")
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return util.PEMToAES(pem)
}

func (ks *fileKeyStore) getSuffix(alias string) string {
	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), alias) {
			if strings.HasSuffix(f.Name(), "sk") {
				return "sk"
			}
			if strings.HasSuffix(f.Name(), "pk") {
				return "pk"
			}
			if strings.HasSuffix(f.Name(), "key") {
				return "key"
			}
			break
		}
	}
	return ""
}

func (ks *fileKeyStore) storeKey(alias string, key []byte) error {
	pem := util.AESToPEM(key)
	return ioutil.WriteFile(ks.getPathForAlias(alias, "key"), pem, 0600)
}

func (ks *fileKeyStore) storePublicKey(alias string, publicKey interface{}) error {
	rawKey, err := util.PublicKeyToPEM(publicKey)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(ks.getPathForAlias(alias, "pk"), rawKey, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (ks *fileKeyStore) storePrivateKey(alias string, privateKey interface{}) error {
	rawKey, err := util.PrivateKeyToPEM(privateKey)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(ks.getPathForAlias(alias, "sk"), rawKey, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (ks *fileKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ks.path, alias+"_"+suffix)
}

func (ks *fileKeyStore) initialize() error {
	if len(ks.path) == 0 {
		return errors.New("An invalid KeyStore path provided. Path cannot be an empty string")
	}

	ks.m.Lock()
	defer ks.m.Unlock()

	if ks.isOpen {
		return errors.New("KeyStore already initialized")
	}

	err := ks.createDirectoryIfNotExists()
	if err != nil {
		return err
	}

	ks.isOpen = true
	return nil
}

func (ks *fileKeyStore) createDirectoryIfNotExists() error {
	ksPath := ks.path
	missing, err := dirMissingOrEmpty(ksPath)
	if err != nil {
		return err
	}

	if missing {
		err := os.MkdirAll(ksPath, 0755)
		if err != nil {
			return err
		}
	}

	return nil
}

func dirMissingOrEmpty(path string) (bool, error) {
	exists, err := directoryExists(path)
	if err != nil {
		return false, err
	}
	if !exists {
		return true, nil
	}

	empty, err := directoryEmpty(path)
	if err != nil {
		return false, nil
	}
	if empty {
		return true, nil
	}
	return false, nil
}

func directoryExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func directoryEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, nil
}
