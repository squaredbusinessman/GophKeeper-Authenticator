package login

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/password"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/token"
)

// Repository ищет пользователя по login для проверки входа
type Repository interface {
	FindUserByLogin(context.Context, string) (User, error)
}

// PasswordVerifier проверяет пароль входа по сохраненному hash
type PasswordVerifier interface {
	Verify(password string, hash string) (bool, error)
}

// PasswordVerifierFunc адаптер функции проверки пароля к интерфейсу PasswordVerifier
type PasswordVerifierFunc func(string, string) (bool, error)

// Verify вызывает функцию проверки пароля входа
func (f PasswordVerifierFunc) Verify(loginPassword string, passwordHash string) (bool, error) {
	return f(loginPassword, passwordHash)
}

// TokenIssuer выпускает access token для пользователя
type TokenIssuer interface {
	Issue(userID string) (token.AccessToken, error)
}

// Service выполняет use case входа пользователя
type Service struct {
	repository       Repository
	passwordVerifier PasswordVerifier
	tokenIssuer      TokenIssuer
}

// NewService создает use case входа пользователя
func NewService(repo Repository, passwordVerifier PasswordVerifier, tokenIssuer TokenIssuer) *Service {
	if passwordVerifier == nil {
		passwordVerifier = PasswordVerifierFunc(password.Verify)
	}

	return &Service{
		repository:       repo,
		passwordVerifier: passwordVerifier,
		tokenIssuer:      tokenIssuer,
	}
}

// Login проверяет пароль входа и возвращает access token с encrypted vault metadata
func (s *Service) Login(ctx context.Context, input Input) (Result, error) {
	login := strings.TrimSpace(input.Login)
	if login == "" {
		return Result{}, fmt.Errorf("%w: login is required", ErrInvalidInput)
	}

	if input.LoginPassword == "" {
		return Result{}, fmt.Errorf("%w: password is required", ErrInvalidInput)
	}

	user, err := s.repository.FindUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return Result{}, ErrInvalidCredentials
		}

		return Result{}, fmt.Errorf("find user by login: %w", err)
	}

	passwordOK, err := s.passwordVerifier.Verify(input.LoginPassword, user.PasswordHash)
	if err != nil {
		return Result{}, fmt.Errorf("verify password: %w", err)
	}

	if !passwordOK {
		return Result{}, ErrInvalidCredentials
	}

	accessToken, err := s.tokenIssuer.Issue(user.ID)
	if err != nil {
		return Result{}, fmt.Errorf("issue access token: %w", err)
	}

	return Result{
		UserID:               user.ID,
		AccessToken:          accessToken.Value,
		AccessTokenExpiresAt: accessToken.ExpiresAt,
		VaultKey:             user.VaultKey,
	}, nil
}
