// Package vaultkey генерирует, шифрует и расшифровывает ключ пользовательского хранилища
package vaultkey

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeyLength задает длину vault key в байтах
	KeyLength = 32

	// KDFAlgorithm содержит название KDF для получения key-encryption key из мастер-пароля
	KDFAlgorithm = "argon2id"
	// EncryptionAlgorithm содержит название алгоритма шифрования vault key
	EncryptionAlgorithm = "xchacha20poly1305"
)

// KDFParams описывает параметры получения key-encryption key из мастер-пароля
type KDFParams struct {
	// Algorithm содержит название KDF
	Algorithm string
	// Salt содержит случайную соль KDF
	Salt []byte
	// TimeCost задает количество проходов Argon2id
	TimeCost uint32
	// MemoryKiB задает объем памяти Argon2id в KiB
	MemoryKiB uint32
	// Parallelism задает уровень параллелизма Argon2id
	Parallelism uint8
	// KeyLength задает длину key-encryption key в байтах
	KeyLength uint32
}

// Envelope содержит зашифрованный vault key и параметры для его расшифровки на клиенте
type Envelope struct {
	// EncryptedVaultKey содержит vault key, зашифрованный через key-encryption key
	EncryptedVaultKey []byte
	// Nonce содержит одноразовое значение для AEAD-расшифровки vault key
	Nonce []byte
	// EncryptionAlg содержит название алгоритма шифрования vault key
	EncryptionAlg string
	// KDFParams содержит параметры получения key-encryption key из мастер-пароля
	KDFParams KDFParams
}

// DefaultKDFParams содержит параметры Argon2id для шифрования vault key по умолчанию
var DefaultKDFParams = KDFParams{
	Algorithm:   KDFAlgorithm,
	TimeCost:    3,
	MemoryKiB:   64 * 1024,
	Parallelism: 4,
	KeyLength:   chacha20poly1305.KeySize,
}

// ValidateConfig проверяет KDF-параметры до генерации соли при шифровании
func (p *KDFParams) ValidateConfig() error {
	if p.Algorithm != "" && p.Algorithm != KDFAlgorithm {
		return fmt.Errorf("unsupported kdf algorithm: %s", p.Algorithm)
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

// Validate проверяет полные KDF-параметры с обязательной солью
func (p *KDFParams) Validate() error {
	if err := p.ValidateConfig(); err != nil {
		return err
	}

	if len(p.Salt) == 0 {
		return fmt.Errorf("kdf salt is required")
	}

	return nil
}

// Validate проверяет полноту envelope перед расшифровкой vault key
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

// Generate создает новый криптостойкий vault key
func Generate() ([]byte, error) {
	key := make([]byte, KeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("unable to generate vault key: %w", err)
	}

	return key, nil
}

// Encrypt шифрует vault key мастер-паролем с параметрами KDF по умолчанию
func Encrypt(masterPass string, vaultKey []byte) (Envelope, error) {
	return EncryptWithParams(masterPass, vaultKey, DefaultKDFParams)
}

// EncryptWithParams шифрует vault key мастер-паролем с переданными параметрами KDF
func EncryptWithParams(masterPass string, vaultKey []byte, params KDFParams) (Envelope, error) {
	if masterPass == "" {
		return Envelope{}, fmt.Errorf("master pass cannot be empty")
	}

	if len(vaultKey) != KeyLength {
		return Envelope{}, fmt.Errorf("vault key length must be %d bytes", KeyLength)
	}

	if err := params.ValidateConfig(); err != nil {
		return Envelope{}, fmt.Errorf("invalid KDF params: %w", err)
	}

	params.Algorithm = KDFAlgorithm

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return Envelope{}, fmt.Errorf("unable to generate salt: %w", err)
	}

	params.Salt = salt

	keyEncryptionKey := deriveKey(masterPass, params)

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
		KDFParams:         params,
	}, nil
}

// Decrypt расшифровывает vault key мастер-паролем и данными из envelope
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

	if len(vaultKey) != KeyLength {
		return nil, fmt.Errorf("decrypted vault key length must be %d bytes", KeyLength)
	}

	return vaultKey, nil
}

func deriveKey(masterPass string, params KDFParams) []byte {
	return argon2.IDKey(
		[]byte(masterPass),
		params.Salt,
		params.TimeCost,
		params.MemoryKiB,
		params.Parallelism,
		params.KeyLength,
	)
}
