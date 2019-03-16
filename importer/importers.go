package importer

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/key"
	"github.com/rkcloudchain/cccsp/util"
)

// New returns creates a new KeyImporter
func New(algo Algorithm) cccsp.KeyImporter {
	if algo == AES256 {
		return &aes256KeyImporter{}
	}
	if algo == HMAC {
		return &hmacKeyImporter{}
	}
	if algo == ECDSAPRIKEY {
		return &ecdsaPrivateKeyImporter{}
	}
	if algo == ECDSAPUBKEY {
		return &ecdsaPublicKeyImporter{}
	}
	if algo == RSAPRIKEY {
		return &rsaPrivateKeyImporter{}
	}
	if algo == RSAPUBKEY {
		return &rsaPublicKeyImporter{}
	}
	if algo == X509CERT {
		return &x509CertificateKeyImporter{}
	}

	panic(errors.Errorf("Unsupported algorithm %s", algo))
}

type aes256KeyImporter struct{}

func (*aes256KeyImporter) KeyImport(raw interface{}) (cccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material, expected byte slice")
	}
	if aesRaw == nil {
		return nil, errors.New("Invalid raw material, it must not be nil")
	}
	if len(aesRaw) != 32 {
		return nil, errors.Errorf("Invalid key length [%d], must be 32 bytes", len(aesRaw))
	}

	return key.New(aesRaw)
}

type hmacKeyImporter struct{}

func (*hmacKeyImporter) KeyImport(raw interface{}) (cccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material, expected byte slice")
	}
	if len(aesRaw) == 0 {
		return nil, errors.New("Invalid raw material, it must not be nil")
	}

	return key.New(aesRaw)
}

type ecdsaPublicKeyImporter struct{}

func (*ecdsaPublicKeyImporter) KeyImport(raw interface{}) (cccsp.Key, error) {
	switch r := raw.(type) {
	case []byte:
		if len(r) == 0 {
			return nil, errors.New("Invalid raw material, it must not be nil")
		}

		cert, err := x509.ParsePKIXPublicKey(r)
		if err != nil {
			return nil, errors.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
		}

		pk, ok := cert.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("Failed casting to ECDSA public key, invalid raw material")
		}

		return key.New(pk)

	case *ecdsa.PublicKey:
		return key.New(r)

	default:
		return nil, errors.New("Invalid raw material, expected byte slice or *ecdsa.PublicKey")
	}
}

type ecdsaPrivateKeyImporter struct{}

func (*ecdsaPrivateKeyImporter) KeyImport(raw interface{}) (cccsp.Key, error) {
	switch r := raw.(type) {
	case []byte:
		if len(r) == 0 {
			return nil, errors.New("Invalid raw material, it must not be nil")
		}

		k, err := util.DERToPrivateKey(r)
		if err != nil {
			return nil, errors.Errorf("Failed converting PKIX to ECDSA private key [%s]", err)
		}

		pk, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("Failed casting to ECDSA private key, invalid raw material")
		}

		return key.New(pk)

	case *ecdsa.PrivateKey:
		return key.New(r)

	default:
		return nil, errors.New("Invalid raw material, expected byte slice or *ecdsa.PrivateKey")
	}
}

type rsaPublicKeyImporter struct{}

func (*rsaPublicKeyImporter) KeyImport(raw interface{}) (cccsp.Key, error) {
	switch r := raw.(type) {
	case []byte:
		if len(r) == 0 {
			return nil, errors.New("Invalid raw material, it must not be nil")
		}

		cert, err := x509.ParsePKIXPublicKey(r)
		if err != nil {
			return nil, errors.Errorf("Failed converting PKIX to RSA public key [%s]", err)
		}

		pk, ok := cert.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("Failed casting to RSA public key, invalid raw material")
		}

		return key.New(pk)

	case *rsa.PublicKey:
		return key.New(r)

	default:
		return nil, errors.New("Invalid raw material, expected byte slice or *rsa.PublicKey")
	}
}

type rsaPrivateKeyImporter struct{}

func (*rsaPrivateKeyImporter) KeyImport(raw interface{}) (cccsp.Key, error) {
	switch r := raw.(type) {
	case []byte:
		if len(r) == 0 {
			return nil, errors.New("Invalid raw material, it must not be nil")
		}

		k, err := util.DERToPrivateKey(r)
		if err != nil {
			return nil, errors.Errorf("Failed converting PKIX to RSA private key [%s]", err)
		}

		pk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("Failed casting to RSA private key, invalid raw material")
		}

		return key.New(pk)

	case *rsa.PrivateKey:
		return key.New(r)

	default:
		return nil, errors.New("Invalid raw material, expected byte slice or *rsa.PrivateKey")
	}
}

type x509CertificateKeyImporter struct{}

func (*x509CertificateKeyImporter) KeyImport(raw interface{}) (cccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material, expected *x509.Certificate")
	}

	switch x509Cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return key.New(x509Cert.PublicKey)
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
	}
}
