/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cccsp

import (
	"crypto"
	"hash"
)

// KeyGenerator is a CCCSP-like interface that provides key generation algorithms.
type KeyGenerator interface {
	KeyGenerate() (Key, error)
}

// Hasher is a CCCSP-like interface that provides hash algorithms
type Hasher interface {
	Hash(msg []byte) ([]byte, error)
	GetHash() hash.Hash
}

// Encryptor is a CCCSP-like interface that provides encryption algorithms
type Encryptor interface {
	Encrypt(k Key, plaintext []byte, opts EncrypterOpts) ([]byte, error)
}

// Decryptor is a CCCSP-like interface that provides decryption algorithms
type Decryptor interface {
	Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) ([]byte, error)
}

// Signer is a CCCSP-like interface that provides signing algorithms
type Signer interface {
	Sign(k Key, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Verifier is a CCCSP-like interface that provides verifying algorithms
type Verifier interface {
	Verify(k Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error)
}

// KeyImporter is a CCCSP-like interface that provides key import algorithm
type KeyImporter interface {
	KeyImport(raw interface{}) (Key, error)
}
