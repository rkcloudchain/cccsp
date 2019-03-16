package provider

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	csp, err := New(tempDir)
	require.NoError(t, err)

	k, err := csp.KeyGenerate("ECDSA384", true)
	assert.NoError(t, err)
	assert.NotNil(t, k)

	s, err := NewSigner(csp, k)
	assert.NoError(t, err)

	pk := s.Public()
	assert.NotNil(t, pk)

	digest := []byte("bla bla bla")
	sigma, err := s.Sign(rand.Reader, digest, nil)
	assert.NoError(t, err)
	assert.NotZero(t, len(sigma))
}
