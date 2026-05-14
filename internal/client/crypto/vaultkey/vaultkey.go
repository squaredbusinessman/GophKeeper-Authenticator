// Package vaultkey генерирует, шифрует и расшифровывает ключ пользовательского хранилища
package vaultkey

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	VaultKeyLength = 32

	KDFAlgorithm        = "argon2id"
	EncryptionAlgorithm = "xchacha20poly1305"
)

type KDFParams struct {
	Algorithm   string
	Salt        []byte
	TimeCost    uint32
	MemoryKiB   uint32
	Parallelism uint8
	KeyLength   uint32
}

type Envelope struct {
	EncryptedVaultKey []byte
	Nonce             []byte
	EncryptionAlg     string
	KDFParams         KDFParams
}

var DefaultKDFParams = KDFParams{
	Algorithm:   KDFAlgorithm,
	TimeCost:    3,
	MemoryKiB:   64 * 1024,
	Parallelism: 4,
	KeyLength:   chacha20poly1305.KeySize,
}

func (p *KDFParams) Validate() error {
	if p.Algorithm != "" && p.Algorithm != KDFAlgorithm {
		return fmt.Errorf("unsupported kdf algorithm: %s", p.Algorithm)
	}

	if len(p.Salt) == 0 {
		return fmt.Errorf("kdf salt is required")
	}

	if p.TimeCost == 0 {
		return fmt.Errorf("kdf time cost must be greater than zero")
	}

	if p.MemoryKiB == 0 {
		return fmt.Errorf("kdf memory must be greater than zero")
	}

	if p.Parallelism == 0 {
		return fmt.Errorf("kdf parallelism must be greater than zero")
	}

	if p.KeyLength != chacha20poly1305.KeySize {
		return fmt.Errorf("kdf key length must be %d bytes", chacha20poly1305.KeySize)
	}

	return nil
}

func (e *Envelope) Validate() error {
	if len(e.EncryptedVaultKey) == 0 {
		return fmt.Errorf("encrypted vault key is required")
	}

	if len(e.Nonce) != chacha20poly1305.NonceSizeX {
		return fmt.Errorf("nonce must be %d bytes", chacha20poly1305.NonceSizeX)
	}

	if e.EncryptionAlg != EncryptionAlgorithm {
		return fmt.Errorf("unsupported encryption algorithm: %s", e.EncryptionAlg)
	}

	if err := e.KDFParams.Validate(); err != nil {
		return err
	}

	return nil
}

func Generate() ([]byte, error) {
	key := make([]byte, VaultKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("unable to generate vault key: %w", err)
	}

	return key, nil
}

func Encrypt(masterPass string, vaultKey []byte) (Envelope, error) {
	return EncryptWithParams(masterPass, vaultKey, DefaultKDFParams)
}

func EncryptWithParams(masterPass string, vaultKey []byte, KDFParams KDFParams) (Envelope, error) {
	if masterPass == "" {
		return Envelope{}, fmt.Errorf("master pass cannot be empty")
	}

	if len(vaultKey) != VaultKeyLength {
		return Envelope{}, fmt.Errorf("vault key length must be %d bytes", VaultKeyLength)
	}

	if err := KDFParams.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("invalid KDF params: %w", err)
	}

	KDFParams.Algorithm = KDFAlgorithm

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return Envelope{}, fmt.Errorf("unable to generate salt: %w", err)
	}

	KDFParams.Salt = salt

	keyEncryptionKey := deriveKey(masterPass, KDFParams)

	aead, err := chacha20poly1305.NewX(keyEncryptionKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("unable to generate key cipher: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("unable to generate key nonce: %w", err)
	}

	encryptedVaultKey := aead.Seal(nil, nonce, vaultKey, nil)

	return Envelope{
		EncryptedVaultKey: encryptedVaultKey,
		Nonce:             nonce,
		EncryptionAlg:     EncryptionAlgorithm,
		KDFParams:         KDFParams,
	}, nil
}

func Decrypt(masterPass string, envelope Envelope) ([]byte, error) {
	if masterPass == "" {
		return nil, fmt.Errorf("master pass cannot be empty")
	}

	if err := envelope.Validate(); err != nil {
		return nil, fmt.Errorf("validate vault key envelope: %w", err)
	}

	keyEncryptionKey := deriveKey(masterPass, envelope.KDFParams)

	aead, err := chacha20poly1305.NewX(keyEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("unable to generate key cipher: %w", err)
	}

	vaultKey, err := aead.Open(nil, envelope.Nonce, envelope.EncryptedVaultKey, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt vault key: %w", err)
	}

	if len(vaultKey) != VaultKeyLength {
		return nil, fmt.Errorf("decrypted vault key length must be %d bytes", VaultKeyLength)
	}

	return vaultKey, nil
}

func deriveKey(masterPass string, KDFParams KDFParams) []byte {
	return argon2.IDKey(
		[]byte(masterPass),
		KDFParams.Salt,
		KDFParams.TimeCost,
		KDFParams.MemoryKiB,
		KDFParams.Parallelism,
		KDFParams.KeyLength,
	)
}
