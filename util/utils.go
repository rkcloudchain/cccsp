/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"

	"github.com/pkg/errors"
)

// PrivateKeyToDER marshals a private key to der
func PrivateKeyToDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid ecdsa private key, it must be different from nil")
	}

	return x509.MarshalECPrivateKey(privateKey)
}

// PEMToPrivateKey unmsrshals a pem to private key
func PEMToPrivateKey(raw []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM, it must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.Errorf("Failed decoding PEM, block must be different from nil, [% x]", raw)
	}

	return DERToPrivateKey(block.Bytes)
}

// DERToPrivateKey unmarshals a der to private key
func DERToPrivateKey(der []byte) (key interface{}, err error) {
	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("Invalid key type, the DER must contains an rsa.PrivateKey or ecdsa.PrivateKey")
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// PrivateKeyToPEM converts the private key to PEM format.
func PrivateKeyToPEM(privateKey interface{}) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid key, it must be different from nil")
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key, it must be different from nil")
		}

		oidNamedCurve, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("Unknow elliptic curve")
		}

		// based on https://golang.org/src/crypto/x509/sec1.go
		privateKeyBytes := k.D.Bytes()
		paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
		copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

		asn1Bytes, err := asn1.Marshal(ecPrivateKey{
			Version:    1,
			PrivateKey: paddedPrivateKey,
			PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
		})

		if err != nil {
			return nil, errors.Errorf("Error marshalling EC key to asn1 [%s]", err)
		}

		pkcs8Key := pkcs8Info{
			Version:             0,
			PrivateKeyAlgorithm: []asn1.ObjectIdentifier{oidPublicKeyECDSA, oidNamedCurve},
			PrivateKey:          asn1Bytes,
		}
		pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
		if err != nil {
			return nil, errors.Errorf("Error marshalling EC key to asn1 [%s]", err)
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}), nil

	case *rsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid rsa private key, it must be different from nil")
		}
		raw := x509.MarshalPKCS1PrivateKey(k)

		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: raw}), nil

	default:
		return nil, errors.New("Invalid key type, it must be *ecdsa.PrivateKey or *rsa.PrivateKey")
	}
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

// PublicKeyToPEM marshals a public key to the PEM format
func PublicKeyToPEM(publicKey interface{}) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid public key, it must be different from nil")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key, it must be different from nil")
		}

		pubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1}), nil

	case *rsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid rsa public key, it must be different from nil")
		}

		pubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubASN1}), nil

	default:
		return nil, errors.New("Invalid key type, it must be *ecdsa.PublicKey or *rsa.PublicKey")
	}
}

// AESToPEM encapsulates an AES key in the PEM format
func AESToPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
}

// PEMToAES extracts from the PEM an AES key
func PEMToAES(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM, it must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.Errorf("Failed decoding PEM, block must be different from nil, [% x]", raw)
	}

	return block.Bytes, nil
}

// PEMToPublicKey unmarshals a PEM to public key
func PEMToPublicKey(raw []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM, it must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.Errorf("Failed decoding, block must be different from nil, [% x]", raw)
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}
