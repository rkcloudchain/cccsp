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
func NewSigner(algo Algorithm) cccsp.Signer {
	if algo == ECDSA {
		return &ecdsaSigner{}
	}
	if algo == RSA {
		return &rsaSigner{}
	}

	panic(errors.Errorf("Unsupported algorithm %s", algo))
}

// NewVerifier creates a new verifier
func NewVerifier(algo Algorithm, public bool) cccsp.Verifier {
	if algo == ECDSA {
		if public {
			return &ecdsaPublicKeyVerifier{}
		}
		return &ecdsaPrivateKeyVerifier{}
	}
	if algo == RSA {
		if public {
			return &rsaPublicKeyVerifier{}
		}
		return &rsaPrivateKeyVerifier{}
	}

	panic(errors.Errorf("Unsupported alogrithm %s", algo))
}

type rsaSigner struct{}

func (s *rsaSigner) Sign(k cccsp.Key, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("Invalid options, must be different from nil")
	}

	return k.(*key.RSAPrivateKey).PrivateKey.Sign(rand.Reader, digest, opts)
}

type rsaPrivateKeyVerifier struct{}

func (v *rsaPrivateKeyVerifier) Verify(k cccsp.Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error) {
	if opts == nil {
		return false, errors.New("Invalid options, it must not be nil")
	}
	switch opts.(type) {
	case *rsa.PSSOptions:
		err := rsa.VerifyPSS(&k.(*key.RSAPrivateKey).PublicKey, opts.(*rsa.PSSOptions).Hash, digest, signature, opts.(*rsa.PSSOptions))
		return err == nil, err
	default:
		err := rsa.VerifyPKCS1v15(&k.(*key.RSAPrivateKey).PublicKey, opts.HashFunc(), digest, signature)
		return err == nil, err
	}
}

type rsaPublicKeyVerifier struct{}

func (v *rsaPublicKeyVerifier) Verify(k cccsp.Key, signature, digest []byte, opts crypto.SignerOpts) (bool, error) {
	if opts == nil {
		return false, errors.New("Invalid options, it must not be nil")
	}
	switch opts.(type) {
	case *rsa.PSSOptions:
		err := rsa.VerifyPSS(k.(*key.RSAPublicKey).PublicKey, opts.(*rsa.PSSOptions).Hash, digest, signature, opts.(*rsa.PSSOptions))
		return err == nil, err
	default:
		err := rsa.VerifyPKCS1v15(k.(*key.RSAPublicKey).PublicKey, opts.HashFunc(), digest, signature)
		return err == nil, err
	}
}
