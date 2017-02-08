package cipher

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/jacobsa/crypto/siv"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD ciphers

func aesGCM(key []byte, nonceSize int) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if nonceSize > 0 {
		return cipher.NewGCMWithNonceSize(blk, nonceSize)
	}
	return cipher.NewGCM(blk)
}

// AES-GCM with standard 12-byte nonce
func AESGCM(key []byte) (cipher.AEAD, error) { return aesGCM(key, 0) }

// AES-GCM with 16-byte nonce for better collision avoidance.
func AESGCM16(key []byte) (cipher.AEAD, error) { return aesGCM(key, 16) }

func Chacha20IETFPoly1305(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) }

type aesSIV []byte

func (key aesSIV) NonceSize() int { return 16 }
func (key aesSIV) Overhead() int  { return 16 }
func (key aesSIV) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	b := make([]byte, key.Overhead()+len(plaintext))
	_, err := siv.Encrypt(b[:0], key, plaintext, [][]byte{additionalData, nonce})
	if err != nil {
		panic(err)
	}
	copy(dst[:len(b)], b)
	return dst[:len(b)]
}
func (key aesSIV) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	b, err := siv.Decrypt(key, ciphertext, [][]byte{additionalData, nonce})
	copy(dst[:len(b)], b)
	return dst[:len(b)], err
}

// AES-SIV mode. Key size must be 32/48/64 bytes.
func AESSIV(key []byte) (cipher.AEAD, error) { return aesSIV(key), nil }
