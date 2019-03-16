package provider

import (
	"crypto"
	"crypto/x509"
	"io"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
)

// cccspSigner is the implementation of a crypto.Signer
type cccspSigner struct {
	csp cccsp.CCCSP
	key cccsp.Key
	pk  crypto.PublicKey
}

// NewSigner returns a crypto.Signer for the given cccsp instance and key
func NewSigner(csp cccsp.CCCSP, key cccsp.Key) (crypto.Signer, error) {
	if csp == nil {
		return nil, errors.New("cccsp instance must be different from nil")
	}
	if key == nil {
		return nil, errors.New("key must be different from nil")
	}

	pub, err := key.Public()
	if err != nil {
		return nil, errors.Wrap(err, "Failed getting public key")
	}

	raw, err := pub.Raw()
	if err != nil {
		return nil, errors.Wrap(err, "Failed marshalling public key")
	}

	pk, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "Failed marshalling der to public key")
	}

	return &cccspSigner{csp, key, pk}, nil
}

func (s *cccspSigner) Public() crypto.PublicKey {
	return s.pk
}

func (s *cccspSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.csp.Sign(s.key, digest, opts)
}
