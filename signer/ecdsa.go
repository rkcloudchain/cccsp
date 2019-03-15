package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/key"
)

type ecdsaSigner struct{}

func (s *ecdsaSigner) Sign(k cccsp.Key, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signECDSA(k.(*key.ECDSAPrivateKey).PrivateKey, digest)
}

func signECDSA(k *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = toLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return marshalECDSASignature(r, s)
}

type ecdsaPrivateKeyVerifier struct{}

func (v *ecdsaPrivateKeyVerifier) Verify(k cccsp.Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error) {
	return verifyECDSA(&k.(*key.ECDSAPrivateKey).PublicKey, signature, digest)
}

type ecdsaPublicKeyVerifier struct{}

func (v *ecdsaPublicKeyVerifier) Verify(k cccsp.Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error) {
	return verifyECDSA(k.(*key.ECDSAPublicKey).PublicKey, signature, digest)
}

func verifyECDSA(k *ecdsa.PublicKey, signature, digest []byte) (bool, error) {
	r, s, err := unmarshalECDSASignature(signature)
	if err != nil {
		return false, errors.Errorf("Failed unmarshalling signature [%s]", err)
	}

	lowS, err := isLowS(k, s)
	if err != nil {
		return false, err
	}

	if !lowS {
		return false, errors.Errorf("Invalid S, must be smaller than half the order [%s][%s]", s, curveHalfOrdersAt(k.Curve))
	}

	return ecdsa.Verify(k, digest, r, s), nil
}
