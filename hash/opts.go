/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hash

const (
	// SHA2 is an identifier for SHA2 hash family
	SHA2 = "SHA2"
	// SHA3 is an identifier for SHA3 hash family
	SHA3 = "SHA3"
)

// Algorithm defines sha algorithm
type Algorithm string

// vars
var (
	SHA1    Algorithm = "SHA1"
	SHA256  Algorithm = "SHA256"
	SHA384  Algorithm = "SHA384"
	SHA512  Algorithm = "SHA512"
	SHA3256 Algorithm = "SHA3_256"
	SHA3384 Algorithm = "SHA3_384"
	SHA3512 Algorithm = "SHA3_512"
)
