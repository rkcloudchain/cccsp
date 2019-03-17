/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
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

	return pemToPublicKey(raw)
}

func (ks *fileKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "sk")
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return pemToPrivateKey(raw)
}

func (ks *fileKeyStore) loadKey(alias string) ([]byte, error) {
	path := ks.getPathForAlias(alias, "key")
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return pemToAES(pem)
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
	pem := aesToPEM(key)
	return ioutil.WriteFile(ks.getPathForAlias(alias, "key"), pem, 0600)
}

func (ks *fileKeyStore) storePublicKey(alias string, publicKey interface{}) error {
	rawKey, err := publicKeyToPEM(publicKey)
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
	rawKey, err := privateKeyToPEM(privateKey)
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

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func privateKeyToPEM(privateKey interface{}) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid key, it must be different from nil")
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key, it must be different from nil")
		}

		oidNamedCurve, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("Unknow elliptic curve")
		}

		// based on https://golang.org/src/crypto/x509/sec1.go
		privateKeyBytes := k.D.Bytes()
		paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
		copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

		asn1Bytes, err := asn1.Marshal(ecPrivateKey{
			Version:    1,
			PrivateKey: paddedPrivateKey,
			PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
		})

		if err != nil {
			return nil, errors.Errorf("Error marshalling EC key to asn1 [%s]", err)
		}

		pkcs8Key := pkcs8Info{
			Version:             0,
			PrivateKeyAlgorithm: []asn1.ObjectIdentifier{oidPublicKeyECDSA, oidNamedCurve},
			PrivateKey:          asn1Bytes,
		}
		pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
		if err != nil {
			return nil, errors.Errorf("Error marshalling EC key to asn1 [%s]", err)
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}), nil

	case *rsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid rsa private key, it must be different from nil")
		}
		raw := x509.MarshalPKCS1PrivateKey(k)

		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: raw}), nil

	default:
		return nil, errors.New("Invalid key type, it must be *ecdsa.PrivateKey or *rsa.PrivateKey")
	}
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

func publicKeyToPEM(publicKey interface{}) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid public key, it must be different from nil")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key, it must be different from nil")
		}

		pubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1}), nil

	case *rsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid rsa public key, it must be different from nil")
		}

		pubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubASN1}), nil

	default:
		return nil, errors.New("Invalid key type, it must be *ecdsa.PublicKey or *rsa.PublicKey")
	}
}

func aesToPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
}

func pemToAES(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM, it must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.Errorf("Failed decoding PEM, block must be different from nil, [% x]", raw)
	}

	return block.Bytes, nil
}

func pemToPrivateKey(raw []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM, it must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.Errorf("Failed decoding PEM, block must be different from nil, [% x]", raw)
	}

	return util.DERToPrivateKey(block.Bytes)
}

func pemToPublicKey(raw []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM, it must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.Errorf("Failed decoding, block must be different from nil, [% x]", raw)
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}
