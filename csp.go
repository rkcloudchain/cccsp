package cccsp

import (
	"crypto/dsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// csp provides a generic implementation of the CCCSP interface based on wrappers.
type csp struct {
	ks            KeyStore
	keyGenerators map[string]KeyGenerator
	hashers       map[string]Hasher
	encryptors    map[string]Encryptor
	decryptors    map[string]Decryptor
}

// New creates a csp instance
func New() (CCCSP, error) {
	csp := &csp{
		keyGenerators: make(map[string]KeyGenerator),
		hashers:       make(map[string]Hasher),
		encryptors:    make(map[string]Encryptor),
		decryptors:    make(map[string]Decryptor),
	}

	return csp, nil
}

func (csp *csp) KeyGenerate(algorithm KeyGenAlgorithm, ephemeral bool) (Key, error) {
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

func (csp *csp) Encrypt(k Key, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid key, it must not be nil")
	}

	switch opts.(type) {
	case RSAOAEPOpts, *RSAOAEPOpts, RSAPKCS1v15Opts, *RSAPKCS1v15Opts:
		_, ok := k.(*rsaPrivateKey)
		if !ok {
			return nil, errors.New("Key type is incorrect, you must use rsa key")
		}

		encryptor := csp.encryptors[string(RSA)]
		return encryptor.Encrypt(k, plaintext, opts)
	case AESCBCPKCS7Opts, *AESCBCPKCS7Opts:
		_, ok := k.(*aesPrivateKey)
		if !ok {
			return nil, errors.New("Key type is incorrect, you must use aes key")
		}

		encryptor := csp.encryptors[string(AES)]
		return encryptor.Encrypt(k, plaintext, opts)
	default:
		return nil, errors.New("Unsupported encryption options")
	}
}

func (csp *csp) Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid key, it must not be nil")
	}

	switch opts.(type) {
	case RSAOAEPOpts, *RSAOAEPOpts, RSAPKCS1v15Opts, *RSAPKCS1v15Opts:
		_, ok := k.(*rsaPrivateKey)
		if !ok {
			return nil, errors.New("Key type is incorrect, you must use rsa key")
		}

		decryptor := csp.decryptors[string(RSA)]
		return decryptor.Decrypt(k, ciphertext, opts)
	case AESCBCPKCS7Opts, *AESCBCPKCS7Opts:
		_, ok := k.(*aesPrivateKey)
		if !ok {
			return nil, errors.New("Key type is incorrect, you must use aes key")
		}

		decryptor := csp.decryptors[string(AES)]
		return decryptor.Decrypt(k, ciphertext, opts)
	default:
		return nil, errors.New("Unsupported encryption options")
	}
}

// Hash hashes messages using specified hash family.
func (csp *csp) Hash(msg []byte, family HashAlgorithm) ([]byte, error) {
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

func (csp *csp) GetHash(algo HashAlgorithm) (hash.Hash, error) {
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
	csp.addWrapper(string(SHA1), &hasher{hash: sha1.New})
	csp.addWrapper(string(SHA224), &hasher{hash: sha256.New224})
	csp.addWrapper(string(SHA256), &hasher{hash: sha256.New})
	csp.addWrapper(string(SHA512), &hasher{hash: sha512.New})
	csp.addWrapper(string(SHA512224), &hasher{hash: sha512.New512_224})
	csp.addWrapper(string(SHA512256), &hasher{hash: sha512.New512_256})
	csp.addWrapper(string(SHA3224), &hasher{hash: sha3.New224})
	csp.addWrapper(string(SHA3256), &hasher{hash: sha3.New256})
	csp.addWrapper(string(SHA3384), &hasher{hash: sha3.New384})
	csp.addWrapper(string(SHA3512), &hasher{hash: sha3.New512})

	csp.addWrapper(string(ECDSA256), &ecdsaKeyGenerator{curve: elliptic.P256()})
	csp.addWrapper(string(ECDSA384), &ecdsaKeyGenerator{curve: elliptic.P384()})
	csp.addWrapper(string(ECDSA521), &ecdsaKeyGenerator{curve: elliptic.P521()})
	csp.addWrapper(string(DSA2048), &dsaKeyGenerator{size: dsa.L2048N256})
	csp.addWrapper(string(DSA3072), &dsaKeyGenerator{size: dsa.L3072N256})
	csp.addWrapper(string(RSA2048), &rsaKeyGenerator{length: 2048})
	csp.addWrapper(string(RSA3072), &rsaKeyGenerator{length: 3072})
	csp.addWrapper(string(RSA4096), &rsaKeyGenerator{length: 4096})
	csp.addWrapper(string(AES16), &aesKeyGenerator{length: 16})
	csp.addWrapper(string(AES24), &aesKeyGenerator{length: 24})
	csp.addWrapper(string(AES32), &aesKeyGenerator{length: 32})

	csp.addWrapper(string(AES), &aescbcpkcs7Encryptor{})
	csp.addWrapper(string(RSA), &rsaEncryptor{})

	csp.addWrapper(string(AES), &aescbcpkcs7Decryptor{})
	csp.addWrapper(string(RSA), &rsaDecryptor{})
}

func (csp *csp) addWrapper(t string, w interface{}) error {
	if t == "" {
		return errors.New("type cannot be empty")
	}
	if w == nil {
		return errors.New("wrapper cannot be nil")
	}
	switch dt := w.(type) {
	case KeyGenerator:
		csp.keyGenerators[t] = dt
	case Hasher:
		csp.hashers[t] = dt
	default:
		return errors.Errorf("wrapper type not valid")
	}

	return nil
}
