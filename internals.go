package cccsp

// KeyGenerator is a CCCSP-like interface that provides key generation algorithms.
type KeyGenerator interface {
	KeyGenerate() (Key, error)
}

// Hasher is a CCCSP-like interface that provides hash algorithms
type Hasher interface {
	Hash(msg []byte) ([]byte, error)
}
