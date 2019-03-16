package crypto

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/key"
)

// NewEncryptor creates a new encryptor
func NewEncryptor(alog Algorithm) cccsp.Encryptor {
	if alog == AES {
		return &aescbcpkcs7Encryptor{}
	}
	if alog == RSA {
		return &rsaEncryptor{}
	}

	panic(errors.Errorf("Unsupported algorithm: %s", alog))
}

// NewDecryptor creates a new decryptor
func NewDecryptor(alog Algorithm) cccsp.Decryptor {
	if alog == AES {
		return &aescbcpkcs7Decryptor{}
	}
	if alog == RSA {
		return &rsaDecryptor{}
	}

	panic(errors.Errorf("Unsupported algorithm: %s", alog))
}

type rsaEncryptor struct{}

func (e *rsaEncryptor) Encrypt(k cccsp.Key, plaintext []byte, opts cccsp.EncrypterOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("Invalid options, must be different from nil")
	}

	var pk *rsa.PublicKey
	switch kk := k.(type) {
	case *key.RSAPrivateKey:
		pk = &kk.PrivateKey.PublicKey
	case *key.RSAPublicKey:
		pk = kk.PublicKey
	default:
		return nil, errors.New("Invalid key type, must be *key.RSAPrivateKey or *key.RSAPublicKey")
	}

	switch o := opts.(type) {
	case *RSAOAEPOpts:
		return rsa.EncryptOAEP(o.Hash, rand.Reader, pk, plaintext, o.Label)
	case RSAOAEPOpts:
		return e.Encrypt(k, plaintext, &o)
	case *RSAPKCS1v15Opts:
		return rsa.EncryptPKCS1v15(rand.Reader, pk, plaintext)
	case RSAPKCS1v15Opts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return nil, errors.Errorf("Opts type not recognized [%s]", opts)
	}
}

type rsaDecryptor struct{}

func (d *rsaDecryptor) Decrypt(k cccsp.Key, ciphertext []byte, opts cccsp.DecrypterOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("Invalid options, must be different from nil")
	}

	var sk *rsa.PrivateKey
	switch kk := k.(type) {
	case *key.RSAPublicKey:
		return nil, errors.New("Invalid key type, must be *key.RSAPrivateKey, not *key.RSAPublicKey")
	case *key.RSAPrivateKey:
		sk = kk.PrivateKey
	default:
		return nil, errors.New("Invalid key type, must be *key.RSAPrivateKey")
	}

	switch o := opts.(type) {
	case *RSAOAEPOpts:
		return rsa.DecryptOAEP(o.Hash, rand.Reader, sk, ciphertext, o.Label)
	case RSAOAEPOpts:
		return d.Decrypt(k, ciphertext, &o)
	case *RSAPKCS1v15Opts:
		return rsa.DecryptPKCS1v15(rand.Reader, sk, ciphertext)
	case RSAPKCS1v15Opts:
		return d.Decrypt(k, ciphertext, &o)
	default:
		return nil, errors.Errorf("Opts type not recognized [%s]", opts)
	}
}
