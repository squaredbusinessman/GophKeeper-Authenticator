package register

import (
	"context"
	"fmt"
	"strings"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/password"
)

// Repository сохраняет пользователя и зашифрованный vault key
type Repository interface {
	CreateUserWithVault(context.Context, CreateUserWithVaultParams) error
}

// CreateUserWithVaultParams содержит данные для атомарного создания (одна неделимая операция) пользователя и vault
type CreateUserWithVaultParams struct {
	UserID       string
	Login        string
	PasswordHash string
	VaultKey     VaultKeyEnvelope
}

// PasswordHasher хеширует пароль входа пользователя
type PasswordHasher interface {
	Hash(string) (string, error)
}

// PasswordHasherFunc адаптер хеширования к интерфейсу PasswordHasher
type PasswordHasherFunc func(string) (string, error)

// Hash вызывает функцию хеширования пароля входа
func (f PasswordHasherFunc) Hash(loginPassword string) (string, error) {
	return f(loginPassword)
}

// IDGenerator генерирует ID пользователя
type IDGenerator interface {
	NewID() (string, error)
}

// IDGeneratorFunc адаптер функции генерации ID к интерфейсу IDGenerator
type IDGeneratorFunc func() (string, error)

// NewID вызывает функцию генерации ID
func (f IDGeneratorFunc) NewID() (string, error) {
	return f()
}

// Service выполняет use case регистрации пользователя
type Service struct {
	repository     Repository
	passwordHasher PasswordHasher
	idGenerator    IDGenerator
}

// NewService создает use case регистрации пользователя
func NewService(repository Repository, passwordHasher PasswordHasher, idGenerator IDGenerator) *Service {
	if passwordHasher == nil {
		passwordHasher = PasswordHasherFunc(password.Hash)
	}

	if idGenerator == nil {
		idGenerator = IDGeneratorFunc(NewUUID)
	}

	return &Service{
		repository:     repository,
		passwordHasher: passwordHasher,
		idGenerator:    idGenerator,
	}
}

func (s *Service) Register(ctx context.Context, input Input) (Result, error) {
	login := strings.TrimSpace(input.Login)
	if login == "" {
		return Result{}, fmt.Errorf("%w: login is required", ErrInvalidInput)
	}

	if input.LoginPassword == "" {
		return Result{}, fmt.Errorf("%w: login password is required", ErrInvalidInput)
	}

	if err := input.VaultKey.Validate(); err != nil {
		return Result{}, err
	}

	userID, err := s.idGenerator.NewID()
	if err != nil {
		return Result{}, fmt.Errorf("generate user id: %w", err)
	}

	passwordHash, err := s.passwordHasher.Hash(input.LoginPassword)
	if err != nil {
		return Result{}, fmt.Errorf("hash login password: %w", err)
	}

	params := CreateUserWithVaultParams{
		UserID:       userID,
		Login:        login,
		PasswordHash: passwordHash,
		VaultKey:     input.VaultKey,
	}

	if err = s.repository.CreateUserWithVault(ctx, params); err != nil {
		return Result{}, fmt.Errorf("create user with vault: %w", err)
	}

	return Result{UserID: userID}, nil
}
