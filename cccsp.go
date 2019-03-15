package cccsp

import (
	"crypto"
	"hash"
)

// Key represents a cryptographic key
type Key interface {
	// Raw converts this key to its byte representation.
	Raw() ([]byte, error)
}

// EncrypterOpts contains options for encrypting with a CSP.
type EncrypterOpts interface{}

// DecrypterOpts contains options for decrypting with a CSP.
type DecrypterOpts interface{}

// CCCSP is the cloudchain cryptographic service provider that offers
// the implementation of cryptographic standards and algorithms
type CCCSP interface {
	// KeyGenerate generates a key.
	KeyGenerate(algorithm KeyGenAlgorithm, ephemeral bool) (Key, error)

	// Hash hashes messages using specified hash family.
	Hash(msg []byte, family HashAlgorithm) ([]byte, error)

	// GetHash returns and instance of hash.Hash with hash alogrithm
	GetHash(algo HashAlgorithm) (hash.Hash, error)

	// Sign signs digest using key k.
	Sign(k Key, digest []byte, opts crypto.SignerOpts) ([]byte, error)

	// Verify verifies signature against key k and digest.
	Verify(k Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error)

	// Encrypt encrypts plaintext using key k.
	Encrypt(k Key, plaintext []byte, opts EncrypterOpts) ([]byte, error)

	// Decrypt decrypts ciphertext using key k.
	Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) ([]byte, error)
}

// KeyStore represents a storage system for cryptographic keys.
type KeyStore interface {
	LoadKey([]byte) (Key, error)
	StoreKey(Key) error
}
