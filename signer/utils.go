/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"

	"github.com/pkg/errors"
)

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

type ecdsaSignature struct {
	R, S *big.Int
}

func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{r, s})
}

func unmarshalECDSASignature(raw []byte) (*big.Int, *big.Int, error) {
	sig := new(ecdsaSignature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, errors.Errorf("Failed unmarshalling signature [%s]", err)
	}

	if sig.R == nil {
		return nil, nil, errors.New("Invalid signature, R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("Invalid signature, S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("Invalid signature, R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("Invalid signature, S must be larger than zero")
	}

	return sig.R, sig.S, nil
}

func toLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := isLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	if !lowS {
		s.Sub(k.Params().N, s)
		return s, true, nil
	}

	return s, false, nil
}

func isLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, errors.Errorf("curve not recognized [%s]", k.Curve)
	}

	return s.Cmp(halfOrder) != 1, nil
}

func curveHalfOrdersAt(c elliptic.Curve) *big.Int {
	return big.NewInt(0).Set(curveHalfOrders[c])
}
