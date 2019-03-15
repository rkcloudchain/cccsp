package signer

// Algorithm defines sign algorithm
type Algorithm string

// vars
var (
	ECDSA Algorithm = "ECDSA"
	RSA   Algorithm = "RSA"
)
