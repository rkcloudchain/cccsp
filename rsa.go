package cccsp

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/pkg/errors"
)

type rsaEncryptor struct{}

func (e *rsaEncryptor) Encrypt(k Key, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("Invalid options, must be different from nil")
	}

	switch o := opts.(type) {
	case *RSAOAEPOpts:
		return rsa.EncryptOAEP(o.Hash, rand.Reader, &k.(*rsaPrivateKey).privKey.PublicKey, plaintext, o.Label)
	case RSAOAEPOpts:
		return e.Encrypt(k, plaintext, &o)
	case *RSAPKCS1v15Opts:
		return rsa.EncryptPKCS1v15(rand.Reader, &k.(*rsaPrivateKey).privKey.PublicKey, plaintext)
	case RSAPKCS1v15Opts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return nil, errors.Errorf("Opts type not recognized [%s]", opts)
	}
}

type rsaDecryptor struct{}

func (d *rsaDecryptor) Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("Invalid options, must be different from nil")
	}

	switch o := opts.(type) {
	case *RSAOAEPOpts:
		return rsa.DecryptOAEP(o.Hash, rand.Reader, k.(*rsaPrivateKey).privKey, ciphertext, o.Label)
	case RSAOAEPOpts:
		return d.Decrypt(k, ciphertext, &o)
	case *RSAPKCS1v15Opts:
		return rsa.DecryptPKCS1v15(rand.Reader, k.(*rsaPrivateKey).privKey, ciphertext)
	case RSAPKCS1v15Opts:
		return d.Decrypt(k, ciphertext, &o)
	default:
		return nil, errors.Errorf("Opts type not recognized [%s]", opts)
	}
}
