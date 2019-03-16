package importer

// Algorithm defines key import algorithm
type Algorithm string

// vars
var (
	AES256      Algorithm = "AES256"
	HMAC        Algorithm = "HMAC"
	ECDSAPRIKEY Algorithm = "ECDSAPRIKEY"
	ECDSAPUBKEY Algorithm = "ECDSAPUBKEY"
	RSAPRIKEY   Algorithm = "RSAPRIKEY"
	RSAPUBKEY   Algorithm = "RSAPUBKEY"
	X509CERT    Algorithm = "X509CERT"
)
