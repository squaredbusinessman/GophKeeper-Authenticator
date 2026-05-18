// Package login содержит use case входа пользователя
package login

import (
	"errors"
	"time"
)

var (
	// ErrInvalidInput означает некорректные входные данные login
	ErrInvalidInput = errors.New("invalid login input")

	// ErrInvalidCredentials означает неверный login или пароль входа
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrUserNotFound означает, что пользователь с таким login не найден
	ErrUserNotFound = errors.New("user not found")
)

// Input содержит данные для входа пользователя
type Input struct {
	Login         string
	LoginPassword string
}

// Result содержит результат успешного входа
type Result struct {
	UserID               string
	AccessToken          string
	AccessTokenExpiresAt time.Time
	VaultKey             VaultKeyEnvelope
}

// User содержит данные пользователя, необходимые для проверки login
type User struct {
	ID           string
	Login        string
	PasswordHash string
	VaultKey     VaultKeyEnvelope
}

// KDFParams описывает параметры получения key-encryption key из мастер-пароля
type KDFParams struct {
	Algorithm   string
	Salt        []byte
	TimeCost    uint32
	MemoryKiB   uint32
	Parallelism uint32
	KeyLength   uint32
}

// VaultKeyEnvelope содержит encrypted vault key metadata пользователя
type VaultKeyEnvelope struct {
	EncryptedVaultKey []byte
	Nonce             []byte
	EncryptionAlg     string
	KDFParams         KDFParams
}
