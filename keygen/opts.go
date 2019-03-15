package keygen

// Algorithm defines key generation algorithm
type Algorithm string

// vars
var (
	ECDSA256 Algorithm = "ECDSA256"
	ECDSA384 Algorithm = "ECDSA384"
	ECDSA521 Algorithm = "ECDSA521"
	RSA2048  Algorithm = "RSA2048"
	RSA3072  Algorithm = "RSA3072"
	RSA4096  Algorithm = "RSA4096"
	AES16    Algorithm = "AES16"
	AES24    Algorithm = "AES24"
	AES32    Algorithm = "AES32"
)
