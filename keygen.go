package cccsp

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/pkg/errors"
)

type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

func (kg *ecdsaKeyGenerator) KeyGenerate() (Key, error) {
	privKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, errors.Errorf("Failed generating ECDSA key for [%v]: %s", kg.curve, err)
	}

	return &ecdsaPrivateKey{privKey}, nil
}

type dsaKeyGenerator struct {
	size dsa.ParameterSizes
}

func (kg *dsaKeyGenerator) KeyGenerate() (Key, error) {
	params := &dsa.Parameters{}
	if err := dsa.GenerateParameters(params, rand.Reader, kg.size); err != nil {
		return nil, errors.Errorf("Failed generating DSA key for [%d]: %s", kg.size, err)
	}

	privKey := &dsa.PrivateKey{}
	privKey.PublicKey.Parameters = *params
	err := dsa.GenerateKey(privKey, rand.Reader)
	if err != nil {
		return nil, errors.Errorf("Failed generating DSA key for [%d]: %s", kg.size, err)
	}

	return &dsaPrivateKey{privKey}, nil
}

type aesKeyGenerator struct {
	length int
}

func (kg *aesKeyGenerator) KeyGenerate() (Key, error) {
	lowLevelKey, err := randomBytes(kg.length)
	if err != nil {
		return nil, errors.Errorf("Failed generating AES %d key [%s]", kg.length, err)
	}

	return &aesPrivateKey{lowLevelKey, false}, nil
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

func (kg *rsaKeyGenerator) KeyGenerate() (Key, error) {
	lowLevelKey, err := rsa.GenerateKey(rand.Reader, kg.length)
	if err != nil {
		return nil, errors.Errorf("Failed generating RSA %d key [%s]", kg.length, err)
	}

	return &rsaPrivateKey{lowLevelKey}, nil
}
