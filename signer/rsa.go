/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/key"
)

// NewSigner creates a new signer
func NewSigner(algo string) cccsp.Signer {
	if algo == ECDSA {
		return &ecdsaSigner{}
	}
	if algo == RSA {
		return &rsaSigner{}
	}

	panic(errors.Errorf("Unsupported algorithm %s", algo))
}

// NewVerifier creates a new verifier
func NewVerifier(algo string) cccsp.Verifier {
	if algo == ECDSA {
		return &ecdsaVerifier{}
	}
	if algo == RSA {
		return &rsaVerifier{}
	}

	panic(errors.Errorf("Unsupported algorithm %s", algo))
}

type rsaSigner struct{}

func (s *rsaSigner) Sign(k cccsp.Key, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("Invalid options, must be different from nil")
	}

	return k.(*key.RSAPrivateKey).PrivateKey.Sign(rand.Reader, digest, opts)
}

type rsaVerifier struct{}

func (v *rsaVerifier) Verify(k cccsp.Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error) {
	if opts == nil {
		return false, errors.New("Invalid options, it must not be nil")
	}

	var pk *rsa.PublicKey
	switch kk := k.(type) {
	case *key.RSAPrivateKey:
		pk = &kk.PublicKey
	case *key.RSAPublicKey:
		pk = kk.PublicKey
	default:
		return false, errors.New("Invalid key type, must be *key.RSAPrivateKey or *key.RSAPublicKey")
	}

	switch opts.(type) {
	case *rsa.PSSOptions:
		err := rsa.VerifyPSS(pk, opts.(*rsa.PSSOptions).Hash, digest, signature, opts.(*rsa.PSSOptions))
		return err == nil, err
	default:
		err := rsa.VerifyPKCS1v15(pk, opts.HashFunc(), digest, signature)
		return err == nil, err
	}
}
