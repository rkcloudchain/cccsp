/*
Copyright Rockontrol Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

// Algorithm defines sign algorithm
type Algorithm string

// vars
var (
	ECDSA Algorithm = "ECDSA"
	RSA   Algorithm = "RSA"
)
