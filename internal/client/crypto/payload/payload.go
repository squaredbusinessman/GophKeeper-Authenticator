// Package payload шифрует и расшифровывает пользовательские секреты через vault key
package payload

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const (
	// KeyLength задает длину vault key для AES-256 в байтах
	KeyLength = 32

	// NonceLength задает длину nonce для стандартного AES-GCM в байтах
	NonceLength = 12

	// EncryptionAlgorithm содержит название алгоритма шифрования payload
	EncryptionAlgorithm = "aes-256-gcm"
)

// EncryptedPayload содержит зашифрованные пользовательские данные и nonce
type EncryptedPayload struct {
	// Ciphertext содержит зашифрованные данные вместе с authentication tag
	Ciphertext []byte
	// Nonce содержит одноразовое значение для AES-GCM
	Nonce []byte
}

// Validate проверяет полноту зашифрованного payload перед расшифровкой
func (p *EncryptedPayload) Validate() error {
	if len(p.Ciphertext) == 0 {
		return fmt.Errorf("ciphertext is required")
	}

	if len(p.Nonce) != NonceLength {
		return fmt.Errorf("nonce length must be %d bytes", NonceLength)
	}

	return nil
}

// Encrypt шифрует plaintext через vault key
func Encrypt(vaultKey []byte, plaintext []byte) (EncryptedPayload, error) {
	aead, err := newAEAD(vaultKey)
	if err != nil {
		return EncryptedPayload{}, err
	}

	nonce := make([]byte, NonceLength)
	if _, err = rand.Read(nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("could not generate payload nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	return EncryptedPayload{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

// Decrypt расшифровывает payload через vault key
func Decrypt(vaultKey []byte, ep EncryptedPayload) ([]byte, error) {
	if err := ep.Validate(); err != nil {
		return nil, fmt.Errorf("could not validate payload: %w", err)
	}

	aead, err := newAEAD(vaultKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, ep.Nonce, ep.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt payload: %w", err)
	}

	return plaintext, nil
}

func newAEAD(vaultKey []byte) (cipher.AEAD, error) {
	if len(vaultKey) != KeyLength {
		return nil, fmt.Errorf("vault key must be %d bytes", KeyLength)
	}

	block, err := aes.NewCipher(vaultKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create payload cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to create payload aead: %w", err)
	}

	return aead, nil
}
