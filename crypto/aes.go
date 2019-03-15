package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/key"
)

type aescbcpkcs7Encryptor struct{}

func (e *aescbcpkcs7Encryptor) Encrypt(k cccsp.Key, plaintext []byte, opts cccsp.EncrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *AESCBCPKCS7Opts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil")
		}

		tmp := pkcs7Padding(plaintext)
		if len(o.IV) != 0 {
			return aesCBCEncryptWithIV(o.IV, k.(*key.AESPrivateKey).PrivateKey, tmp)
		} else if o.PRNG != nil {
			return aesCBCEncryptWithRand(o.PRNG, k.(*key.AESPrivateKey).PrivateKey, tmp)
		}

		return aesCBCEncryptWithRand(rand.Reader, k.(*key.AESPrivateKey).PrivateKey, tmp)
	case AESCBCPKCS7Opts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return nil, errors.Errorf("Mode not recognized [%s]", opts)
	}
}

func pkcs7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func aesCBCEncryptWithIV(iv []byte, key, s []byte) ([]byte, error) {
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext, it must be a multiple of the block size")
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("Invalid IV, it must have length the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(s))
	copy(ciphertext[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

func aesCBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext, it must be a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(s))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

type aescbcpkcs7Decryptor struct{}

func (d *aescbcpkcs7Decryptor) Decrypt(k cccsp.Key, ciphertext []byte, opts cccsp.DecrypterOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("Invalid options, must be different from nil")
	}

	switch opts.(type) {
	case *AESCBCPKCS7Opts, AESCBCPKCS7Opts:
		pt, err := aesCBCDecrypt(k.(*key.AESPrivateKey).PrivateKey, ciphertext)
		if err == nil {
			return pkcs7UnPadding(pt)
		}
		return nil, err
	default:
		return nil, errors.Errorf("Opts not recognized [%s]", opts)
	}
}

func aesCBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < aes.BlockSize {
		return nil, errors.New("Invalid ciphertext, it must be a multiple of the block size")
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext, it must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(src, src)

	return src, nil
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding, unpadding > aes.BlockSize || unpadding == 0")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding, pad[i] != unpadding")
		}
	}

	return src[:(length - unpadding)], nil
}
