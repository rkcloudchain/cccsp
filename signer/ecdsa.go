/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

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
	var sk *ecdsa.PrivateKey
	switch kk := k.(type) {
	case *key.ECDSAPrivateKey:
		sk = kk.PrivateKey
	default:
		return nil, errors.New("Invalid key type, must be *key.ECDSAPrivateKey")
	}
	return signECDSA(sk, digest)
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

type ecdsaVerifier struct{}

func (v *ecdsaVerifier) Verify(k cccsp.Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error) {
	var pk *ecdsa.PublicKey
	switch kk := k.(type) {
	case *key.ECDSAPrivateKey:
		pk = &kk.PublicKey
	case *key.ECDSAPublicKey:
		pk = kk.PublicKey
	default:
		return false, errors.New("Invalid key type, must be *key.ECDSAPrivateKey or *key.ECDSAPublicKey")
	}

	return verifyECDSA(pk, signature, digest)
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
