package cccsp

import (
	"hash"
	"io"
)

const (
	// SHA2 is an identifier for SHA2 hash family
	SHA2 = "SHA2"
	// SHA3 is an identifier for SHA3 hash family
	SHA3 = "SHA3"
)

// HashAlgorithm defines sha algorithm
type HashAlgorithm string

// vars
var (
	SHA1      HashAlgorithm = "SHA1"
	SHA224    HashAlgorithm = "SHA224"
	SHA256    HashAlgorithm = "SHA256"
	SHA384    HashAlgorithm = "SHA384"
	SHA512    HashAlgorithm = "SHA512"
	SHA512224 HashAlgorithm = "SHA512_224"
	SHA512256 HashAlgorithm = "SHA512_256"
	SHA3224   HashAlgorithm = "SHA3_224"
	SHA3256   HashAlgorithm = "SHA3_256"
	SHA3384   HashAlgorithm = "SHA3_384"
	SHA3512   HashAlgorithm = "SHA3_512"
)

// KeyGenAlgorithm defines key generation algorithm
type KeyGenAlgorithm string

// vars
var (
	ECDSA256 KeyGenAlgorithm = "ECDSA256"
	ECDSA384 KeyGenAlgorithm = "ECDSA384"
	ECDSA521 KeyGenAlgorithm = "ECDSA521"
	DSA2048  KeyGenAlgorithm = "DSA2048"
	DSA3072  KeyGenAlgorithm = "DSA3072"
	RSA2048  KeyGenAlgorithm = "RSA2048"
	RSA3072  KeyGenAlgorithm = "RSA3072"
	RSA4096  KeyGenAlgorithm = "RSA4096"
	AES16    KeyGenAlgorithm = "AES16"
	AES24    KeyGenAlgorithm = "AES24"
	AES32    KeyGenAlgorithm = "AES32"
)

// EncryptionAlgorithm defines encryption algorithm
type EncryptionAlgorithm string

// vars
var (
	AES EncryptionAlgorithm = "AES"
	RSA EncryptionAlgorithm = "RSA"
)

// AESCBCPKCS7Opts contains options for AES encryption in CBC mode with PKCS7 padding.
type AESCBCPKCS7Opts struct {
	// IV is the initialization vector to be used by the underlying cihper.
	IV []byte

	// PRNG is an interface of a PRNG to be used by the underlying cihper.
	PRNG io.Reader
}

// RSAOAEPOpts contains options for RSA-OAEP encryption.
type RSAOAEPOpts struct {
	Label []byte
	Hash  hash.Hash
}

// RSAPKCS1v15Opts contains options for RSA and the padding scheme from PKCS#1 v1.5
type RSAPKCS1v15Opts struct{}
