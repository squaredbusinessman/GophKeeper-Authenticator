// Package password хеширует и проверяет пароль входа пользователя
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	algorithm = "argon2id"
	version   = argon2.Version
)

// Params описывает параметры Argon2id для хеширования пароля входа
type Params struct {
	// Memory задает объем памяти Argon2id в KiB
	Memory uint32
	// Iterations задает количество проходов Argon2id
	Iterations uint32
	// Parallelism задает уровень параллелизма Argon2id
	Parallelism uint8
	// SaltLength задает длину случайной соли в байтах
	SaltLength uint32
	// KeyLength задает длину итогового хеша в байтах
	KeyLength uint32
}

// DefaultParams содержит параметры Argon2id для хеширования пароля входа по умолчанию
var DefaultParams = Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// Validate проверяет корректность параметров Argon2id
func (p *Params) Validate() error {
	if p.Memory <= 0 {
		return fmt.Errorf("password memory must be greater than zero")
	}

	if p.Iterations <= 0 {
		return fmt.Errorf("password iterations must be greater than zero")
	}

	if p.Parallelism <= 0 {
		return fmt.Errorf("password parallelism must be greater than zero")
	}

	if p.SaltLength <= 0 {
		return fmt.Errorf("password salt length must be greater than zero")
	}

	if p.KeyLength <= 0 {
		return fmt.Errorf("password key length must be greater than zero")
	}

	return nil
}

// Hash хеширует пароль входа с параметрами Argon2id по умолчанию
func Hash(password string) (string, error) {
	return HashWithParams(password, DefaultParams)
}

// HashWithParams хеширует пароль входа с переданными параметрами Argon2id
func HashWithParams(password string, params Params) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	if err := params.Validate(); err != nil {
		return "", fmt.Errorf("validate argon2id params: %w", err)
	}

	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		algorithm,
		version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		encodedSalt,
		encodedHash,
	), nil
}

// Verify проверяет пароль входа по сохраненному Argon2id-хешу
func Verify(password, encodedHash string) (bool, error) {
	if password == "" {
		return false, fmt.Errorf("password cannot be empty")
	}

	params, salt, expectedHash, err := Decode(encodedHash)
	if err != nil {
		return false, fmt.Errorf("decode password hash: %w", err)
	}

	actualHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	if subtle.ConstantTimeCompare(actualHash, expectedHash) == 1 {
		return true, nil
	}

	return false, nil
}

// Decode разбирает сохраненный Argon2id-хеш на параметры, соль и байты хеша
func Decode(encodedHash string) (Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return Params{}, nil, nil, fmt.Errorf("invalid password hash format: %s", encodedHash)
	}

	if parts[1] != algorithm {
		return Params{}, nil, nil, fmt.Errorf("unsupported password hash algorithm: %s", parts[1])
	}

	if parts[2] != fmt.Sprintf("v=%d", version) {
		return Params{}, nil, nil, fmt.Errorf("unsupported password hash version: %s", parts[2])
	}

	params, err := parseParams(parts[3])
	if err != nil {
		return Params{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("decode salt from encoded hash: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("decode hash from encoded hash: %w", err)
	}

	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(hash))

	if err := params.Validate(); err != nil {
		return Params{}, nil, nil, fmt.Errorf("validate decoded argon2id params: %w", err)
	}

	return params, salt, hash, nil
}

func parseParams(encodedParams string) (Params, error) {
	parts := strings.Split(encodedParams, ",")
	if len(parts) != 3 {
		return Params{}, fmt.Errorf("invalid argon2id params format: %s", encodedParams)
	}

	values := make(map[string]string, len(parts))
	for _, p := range parts {
		key, value, ok := strings.Cut(p, "=")
		if !ok {
			return Params{}, fmt.Errorf("invalid argon2id param: %s", p)
		}

		values[key] = value
	}

	memory, err := parseUint32(values["m"], "memory")
	if err != nil {
		return Params{}, err
	}

	iterations, err := parseUint32(values["t"], "iterations")
	if err != nil {
		return Params{}, err
	}

	parallelism, err := parseUint8(values["p"], "parallelism")
	if err != nil {
		return Params{}, err
	}

	return Params{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
	}, nil
}

func parseUint32(value string, name string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse argon2id %s: %w", name, err)
	}

	return uint32(parsed), nil
}

func parseUint8(value string, name string) (uint8, error) {
	parsed, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("parse argon2id %s: %w", name, err)
	}

	return uint8(parsed), nil
}
