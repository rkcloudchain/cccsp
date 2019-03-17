# CCCSP

[![Build Status](https://travis-ci.org/rkcloudchain/cccsp.svg?branch=master)](https://travis-ci.org/rkcloudchain/cccsp)
[![codecov](https://codecov.io/gh/rkcloudchain/cccsp/branch/master/graph/badge.svg)](https://codecov.io/gh/rkcloudchain/cccsp)
[![Go Report Card](https://goreportcard.com/badge/github.com/rkcloudchain/cccsp)](https://goreportcard.com/report/github.com/rkcloudchain/cccsp)

cccsp is the CloudChain Cryptographic Service Provider that offers the implementation of cryptographic standards and algorithms.

cccsp provides the following services:

* Encrypt - Encryption operation
* Decrypt - Decryption operation
* Sign - Signature operation
* Verify - Verification operation
* Hash - Hash calculation

cccsp supports a variety of encryption and signature algorithms, including AES, RSA, and ECDSA. Support multiple hash clusters, including sha1, sha256, sha384, sha512, sha3_256, sha3_384, sha3_512.

## Install

With a [correctly configured](https://golang.org/doc/install#testing) Go toolchain:

```sh
go get -u github.com/rkcloudchain/cccsp
```

## Example

Let's start creating a cccsp instance with a keystore path.

```go
csp, _ := provider.New("you keystore path")
```

Now you can generate a new key

```go
key, _ := csp.KeyGenerate("ECDSA256", false)
```

You can sign with the generated key

```go
ptext := []byte("bla bla bla")
sigma, err := csp.Sign(key, ptext, nil)
```

Or verify that the signature is correct

```go
valid, err := csp.Verify(key, sigma, ptext, nil)
```

The cccsp interface defines the following methods:

```go
// CCCSP is the cloudchain cryptographic service provider that offers
// the implementation of cryptographic standards and algorithms
type CCCSP interface {
    // KeyGenerate generates a key.
    KeyGenerate(algorithm string, ephemeral bool) (Key, error)

    // KeyImport imports a key from its raw representation.
    KeyImport(raw interface{}, algorithm string, ephemeral bool) (Key, error)

    // GetKey returns the key this CSP associates to
    GetKey(id []byte) (Key, error)

    // Hash hashes messages using specified hash family.
    Hash(msg []byte, family string) ([]byte, error)

    // GetHash returns and instance of hash.Hash with hash algorithm
    GetHash(algo string) (hash.Hash, error)

    // Sign signs digest using key k.
    Sign(k Key, digest []byte, opts crypto.SignerOpts) ([]byte, error)

    // Verify verifies signature against key k and digest.
    Verify(k Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error)

    // Encrypt encrypts plaintext using key k.
    Encrypt(k Key, plaintext []byte, opts EncrypterOpts) ([]byte, error)

    // Decrypt decrypts ciphertext using key k.
    Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) ([]byte, error)
}
```

In addition to signing and verification, you can also perform encryption, decryption, and hash calculations.

## License

cccsp is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.