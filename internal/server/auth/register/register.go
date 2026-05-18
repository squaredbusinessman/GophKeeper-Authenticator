// Package register содержит use case регистрации пользователя
package register

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidInput означает некорректные входные данные регистрации
	ErrInvalidInput = errors.New("invalid register input")

	// ErrLoginAlreadyExists означает, что пользователь с таким login уже существует
	ErrLoginAlreadyExists = errors.New("login already exists")
)

// Input содержит данные для регистрации пользователя
type Input struct {
	Login         string
	LoginPassword string
	VaultKey      VaultKeyEnvelope
}

// Result содержит id пользователя после регистрации
type Result struct {
	UserID string
}

// KDFParams описывает параметры получения encryption key из мастер-пароля
type KDFParams struct {
	Algorithm   string
	Salt        []byte
	TimeCost    uint32
	MemoryKiB   uint32
	Parallelism uint32
	KeyLength   uint32
}

// Validate проверяет полноту KDF metadata перед сохранением
func (p KDFParams) Validate() error {
	if strings.TrimSpace(p.Algorithm) == "" {
		return fmt.Errorf("%w: kdf algorithm is required", ErrInvalidInput)
	}

	if len(p.Salt) == 0 {
		return fmt.Errorf("%w: kdf salt is required", ErrInvalidInput)
	}

	if p.TimeCost == 0 {
		return fmt.Errorf("%w: kdf time cost must be greater than zero", ErrInvalidInput)
	}

	if p.MemoryKiB == 0 {
		return fmt.Errorf("%w: kdf memory must be greater than zero", ErrInvalidInput)
	}

	if p.Parallelism == 0 {
		return fmt.Errorf("%w: kdf parallelism must be greater than zero", ErrInvalidInput)
	}

	if p.KeyLength == 0 {
		return fmt.Errorf("%w: kdf key length must be greater than zero", ErrInvalidInput)
	}

	return nil
}

// VaultKeyEnvelope содержит зашифрованный vault key и metadata для его открытия на клиенте
type VaultKeyEnvelope struct {
	EncryptedVaultKey []byte
	Nonce             []byte
	EncryptionAlg     string
	KDFParams         KDFParams
}

// Validate проверяет полноту encrypted vault key metadata перед сохранением
func (e *VaultKeyEnvelope) Validate() error {
	if len(e.EncryptedVaultKey) == 0 {
		return fmt.Errorf("%w: encrypted vault key is required", ErrInvalidInput)
	}

	if len(e.Nonce) == 0 {
		return fmt.Errorf("%w: vault key nonce is required", ErrInvalidInput)
	}

	if strings.TrimSpace(e.EncryptionAlg) == "" {
		return fmt.Errorf("%w: vault key encryption algorithm is required", ErrInvalidInput)
	}

	if err := e.KDFParams.Validate(); err != nil {
		return err
	}

	return nil
}
