/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/key"
)

// NewKeyGenerator creates a new key generator
func NewKeyGenerator(algo string) cccsp.KeyGenerator {
	if algo == ECDSA256 {
		return &ecdsaKeyGenerator{curve: elliptic.P256()}
	}
	if algo == ECDSA384 {
		return &ecdsaKeyGenerator{curve: elliptic.P384()}
	}
	if algo == ECDSA521 {
		return &ecdsaKeyGenerator{curve: elliptic.P521()}
	}
	if algo == RSA2048 {
		return &rsaKeyGenerator{length: 2048}
	}
	if algo == RSA3072 {
		return &rsaKeyGenerator{length: 3072}
	}
	if algo == RSA4096 {
		return &rsaKeyGenerator{length: 4096}
	}
	if algo == AES16 {
		return &aesKeyGenerator{length: 16}
	}
	if algo == AES24 {
		return &aesKeyGenerator{length: 24}
	}
	if algo == AES32 {
		return &aesKeyGenerator{length: 32}
	}
	panic(errors.Errorf("Unsupported algorithm %s", algo))
}

type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

func (kg *ecdsaKeyGenerator) KeyGenerate() (cccsp.Key, error) {
	privKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, errors.Errorf("Failed generating ECDSA key for [%v]: %s", kg.curve, err)
	}

	return key.New(privKey)
}

type aesKeyGenerator struct {
	length int
}

func (kg *aesKeyGenerator) KeyGenerate() (cccsp.Key, error) {
	lowLevelKey, err := randomBytes(kg.length)
	if err != nil {
		return nil, errors.Errorf("Failed generating AES %d key [%s]", kg.length, err)
	}

	return key.New(lowLevelKey)
}

func randomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)
	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, errors.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

type rsaKeyGenerator struct {
	length int
}

func (kg *rsaKeyGenerator) KeyGenerate() (cccsp.Key, error) {
	lowLevelKey, err := rsa.GenerateKey(rand.Reader, kg.length)
	if err != nil {
		return nil, errors.Errorf("Failed generating RSA %d key [%s]", kg.length, err)
	}

	return key.New(lowLevelKey)
}
