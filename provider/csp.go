/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"sync"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	rkcrypt "github.com/rkcloudchain/cccsp/crypto"
	rkhash "github.com/rkcloudchain/cccsp/hash"
	"github.com/rkcloudchain/cccsp/importer"
	"github.com/rkcloudchain/cccsp/key"
	"github.com/rkcloudchain/cccsp/keygen"
	"github.com/rkcloudchain/cccsp/signer"
	"golang.org/x/crypto/sha3"
)

var (
	defaultCCCSP cccsp.CCCSP
	once         sync.Once
)

// GetDefault returns a ephemeral CCCSP
func GetDefault() cccsp.CCCSP {
	once.Do(func() {
		defaultCCCSP = New(NewMemoryKeyStore())
	})

	return defaultCCCSP
}

// csp provides a generic implementation of the CCCSP interface based on wrappers.
type csp struct {
	ks            cccsp.KeyStore
	keyGenerators map[string]cccsp.KeyGenerator
	keyImporters  map[string]cccsp.KeyImporter
	hashers       map[string]cccsp.Hasher
	encryptors    map[string]cccsp.Encryptor
	decryptors    map[string]cccsp.Decryptor
	signers       map[string]cccsp.Signer
	verifiers     map[string]cccsp.Verifier
}

// New creates a csp instance
func New(ks cccsp.KeyStore) cccsp.CCCSP {
	csp := &csp{
		ks:            ks,
		keyGenerators: make(map[string]cccsp.KeyGenerator),
		keyImporters:  make(map[string]cccsp.KeyImporter),
		hashers:       make(map[string]cccsp.Hasher),
		encryptors:    make(map[string]cccsp.Encryptor),
		decryptors:    make(map[string]cccsp.Decryptor),
		signers:       make(map[string]cccsp.Signer),
		verifiers:     make(map[string]cccsp.Verifier),
	}
	csp.initialize()

	return csp
}

func (csp *csp) KeyGenerate(algorithm string, ephemeral bool) (cccsp.Key, error) {
	if algorithm == "" {
		return nil, errors.New("Invalid algorithm, it must not be empty")
	}

	kg, found := csp.keyGenerators[string(algorithm)]
	if !found {
		return nil, errors.Errorf("Unsupported algorithm [%s]", algorithm)
	}

	k, err := kg.KeyGenerate()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed generating key with algorithm [%s]", algorithm)
	}

	if !ephemeral {
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", algorithm)
		}
	}

	return k, nil
}

func (csp *csp) KeyImport(raw interface{}, algorithm string, ephemeral bool) (cccsp.Key, error) {
	if raw == nil {
		return nil, errors.New("Invalid raw, it must not be nil")
	}

	keyImporter, found := csp.keyImporters[algorithm]
	if !found {
		return nil, errors.Errorf("Unsupported key import algorithm %s", algorithm)
	}

	k, err := keyImporter.KeyImport(raw)
	if err != nil {
		return nil, errors.Wrap(err, "Failed importing key")
	}

	if !ephemeral {
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrap(err, "Failed storing imported key")
		}
	}

	return k, nil
}

func (csp *csp) GetKey(id []byte) (cccsp.Key, error) {
	k, err := csp.ks.LoadKey(id)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting key for Identifier [%x]", id)
	}

	return k, nil
}

func (csp *csp) Encrypt(k cccsp.Key, plaintext []byte, opts cccsp.EncrypterOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid key, it must not be nil")
	}

	switch k.(type) {
	case *key.RSAPrivateKey:
		encryptor := csp.encryptors[string(rkcrypt.RSA)]
		return encryptor.Encrypt(k, plaintext, opts)
	case *key.AESPrivateKey:
		encryptor := csp.encryptors[string(rkcrypt.AES)]
		return encryptor.Encrypt(k, plaintext, opts)
	default:
		return nil, errors.New("Unsupported encryption options")
	}
}

func (csp *csp) Decrypt(k cccsp.Key, ciphertext []byte, opts cccsp.DecrypterOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid key, it must not be nil")
	}

	switch k.(type) {
	case *key.RSAPrivateKey:
		decryptor := csp.decryptors[string(rkcrypt.RSA)]
		return decryptor.Decrypt(k, ciphertext, opts)
	case *key.AESPrivateKey:
		decryptor := csp.decryptors[string(rkcrypt.AES)]
		return decryptor.Decrypt(k, ciphertext, opts)
	default:
		return nil, errors.New("Unsupported encryption options")
	}
}

func (csp *csp) Sign(k cccsp.Key, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid key, must not be nil")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest, cannot be empty")
	}

	switch k.(type) {
	case *key.RSAPrivateKey:
		s := csp.signers[string(signer.RSA)]
		return s.Sign(k, digest, opts)
	case *key.ECDSAPrivateKey:
		s := csp.signers[string(signer.ECDSA)]
		return s.Sign(k, digest, opts)
	default:
		return nil, errors.New("Unsupported key type")
	}
}

func (csp *csp) Verify(k cccsp.Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error) {
	if k == nil {
		return false, errors.New("Invalid key, must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature, cannot be empty")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest, cannot be empty")
	}

	var keyStr string
	switch k.(type) {
	case *key.RSAPrivateKey, *key.RSAPublicKey:
		keyStr = string(signer.RSA)
	case *key.ECDSAPrivateKey, *key.ECDSAPublicKey:
		keyStr = string(signer.ECDSA)
	default:
		return false, errors.New("Unsupported key type")
	}

	verifier := csp.verifiers[keyStr]
	valid, err := verifier.Verify(k, signature, digest, opts)
	if err != nil {
		return false, errors.Wrapf(err, "Failed verifying with opts [%s]", opts)
	}

	return valid, nil
}

// Hash hashes messages using specified hash family.
func (csp *csp) Hash(msg []byte, family string) ([]byte, error) {
	if family == "" {
		return nil, errors.New("Invalid hash family. It must not be empty")
	}

	hasher, found := csp.hashers[string(family)]
	if !found {
		return nil, errors.Errorf("Unsupported hash family [%s]", family)
	}

	digest, err := hasher.Hash(msg)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed hashing with hash family [%s]", family)
	}

	return digest, nil
}

func (csp *csp) GetHash(algo string) (hash.Hash, error) {
	if algo == "" {
		return nil, errors.New("Invalid algorithm, it must not be empty")
	}

	hasher, found := csp.hashers[string(algo)]
	if !found {
		return nil, errors.Errorf("Unsupported hash algorithm: %s", algo)
	}

	return hasher.GetHash(), nil
}

func (csp *csp) initialize() {
	csp.addWrapper(string(rkhash.SHA1), rkhash.New(sha1.New))
	csp.addWrapper(string(rkhash.SHA256), rkhash.New(sha256.New))
	csp.addWrapper(string(rkhash.SHA384), rkhash.New(sha512.New384))
	csp.addWrapper(string(rkhash.SHA512), rkhash.New(sha512.New))
	csp.addWrapper(string(rkhash.SHA3256), rkhash.New(sha3.New256))
	csp.addWrapper(string(rkhash.SHA3384), rkhash.New(sha3.New384))
	csp.addWrapper(string(rkhash.SHA3512), rkhash.New(sha3.New512))

	csp.addWrapper(string(keygen.ECDSA256), keygen.New(keygen.ECDSA256))
	csp.addWrapper(string(keygen.ECDSA384), keygen.New(keygen.ECDSA384))
	csp.addWrapper(string(keygen.ECDSA521), keygen.New(keygen.ECDSA521))
	csp.addWrapper(string(keygen.RSA2048), keygen.New(keygen.RSA2048))
	csp.addWrapper(string(keygen.RSA3072), keygen.New(keygen.RSA3072))
	csp.addWrapper(string(keygen.RSA4096), keygen.New(keygen.RSA4096))
	csp.addWrapper(string(keygen.AES16), keygen.New(keygen.AES16))
	csp.addWrapper(string(keygen.AES24), keygen.New(keygen.AES24))
	csp.addWrapper(string(keygen.AES32), keygen.New(keygen.AES32))

	csp.addWrapper(string(rkcrypt.AES), rkcrypt.NewEncryptor(rkcrypt.AES))
	csp.addWrapper(string(rkcrypt.RSA), rkcrypt.NewEncryptor(rkcrypt.RSA))

	csp.addWrapper(string(rkcrypt.AES), rkcrypt.NewDecryptor(rkcrypt.AES))
	csp.addWrapper(string(rkcrypt.RSA), rkcrypt.NewDecryptor(rkcrypt.RSA))

	csp.addWrapper(string(signer.ECDSA), signer.NewSigner(signer.ECDSA))
	csp.addWrapper(string(signer.RSA), signer.NewSigner(signer.RSA))

	csp.addWrapper(string(signer.ECDSA), signer.NewVerifier(signer.ECDSA))
	csp.addWrapper(string(signer.RSA), signer.NewVerifier(signer.RSA))

	csp.addWrapper(string(importer.AES256), importer.New(importer.AES256))
	csp.addWrapper(string(importer.HMAC), importer.New(importer.HMAC))
	csp.addWrapper(string(importer.ECDSAPRIKEY), importer.New(importer.ECDSAPRIKEY))
	csp.addWrapper(string(importer.ECDSAPUBKEY), importer.New(importer.ECDSAPUBKEY))
	csp.addWrapper(string(importer.RSAPRIKEY), importer.New(importer.RSAPRIKEY))
	csp.addWrapper(string(importer.RSAPUBKEY), importer.New(importer.RSAPUBKEY))
	csp.addWrapper(string(importer.X509CERT), importer.New(importer.X509CERT))
}

func (csp *csp) addWrapper(t string, w interface{}) error {
	if t == "" {
		return errors.New("type cannot be empty")
	}
	if w == nil {
		return errors.New("wrapper cannot be nil")
	}
	switch dt := w.(type) {
	case cccsp.KeyGenerator:
		csp.keyGenerators[t] = dt
	case cccsp.KeyImporter:
		csp.keyImporters[t] = dt
	case cccsp.Hasher:
		csp.hashers[t] = dt
	case cccsp.Encryptor:
		csp.encryptors[t] = dt
	case cccsp.Decryptor:
		csp.decryptors[t] = dt
	case cccsp.Signer:
		csp.signers[t] = dt
	case cccsp.Verifier:
		csp.verifiers[t] = dt
	default:
		return errors.Errorf("wrapper type not valid")
	}

	return nil
}
