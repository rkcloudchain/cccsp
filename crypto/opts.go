/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"hash"
	"io"
)

// Algorithm defines encryption algorithm
type Algorithm string

// vars
var (
	AES Algorithm = "AES"
	RSA Algorithm = "RSA"
)

// AESCBCPKCS7Opts contains options for AES encryption in CBC mode with PKCS7 padding.
type AESCBCPKCS7Opts struct {
	// IV is the initialization vector to be used by the underlying cihper.
	IV []byte

	// PRNG is an interface of a PRNG to be used by the underlying cihper.
	PRNG io.Reader
}

// RSAOAEPOpts contains options for RSA-OAEP encryption.
type RSAOAEPOpts struct {
	Label []byte
	Hash  hash.Hash
}

// RSAPKCS1v15Opts contains options for RSA and the padding scheme from PKCS#1 v1.5
type RSAPKCS1v15Opts struct{}
