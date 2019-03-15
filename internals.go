package cccsp

import "hash"

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
