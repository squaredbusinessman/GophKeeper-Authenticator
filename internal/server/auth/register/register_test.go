package register

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/token"
)

type fakeRepository struct {
	createFunc func(context.Context, CreateUserWithVaultParams) error
	calls      []CreateUserWithVaultParams
}

func (r *fakeRepository) CreateUserWithVault(ctx context.Context, params CreateUserWithVaultParams) error {
	r.calls = append(r.calls, params)
	if r.createFunc != nil {
		return r.createFunc(ctx, params)
	}

	return nil
}

type fakePasswordHasher struct {
	hashFunc func(string) (string, error)
}

func (h fakePasswordHasher) Hash(password string) (string, error) {
	if h.hashFunc != nil {
		return h.hashFunc(password)
	}

	return "hashed:" + password, nil
}

type fakeIDGenerator struct {
	id  string
	err error
}

func (g fakeIDGenerator) NewID() (string, error) {
	if g.err != nil {
		return "", g.err
	}

	return g.id, nil
}

type fakeTokenIssuer struct {
	token token.AccessToken
	err   error
	calls []string
}

func (i *fakeTokenIssuer) Issue(userID string) (token.AccessToken, error) {
	i.calls = append(i.calls, userID)
	if i.err != nil {
		return token.AccessToken{}, i.err
	}

	return i.token, nil
}

func validInput() Input {
	return Input{
		Login:         "user@example.com",
		LoginPassword: "login-password",
		VaultKey: VaultKeyEnvelope{
			EncryptedVaultKey: []byte("encrypted-vault-key"),
			Nonce:             []byte("vault-key-nonce"),
			EncryptionAlg:     "xchacha20poly1305",
			KDFParams: KDFParams{
				Algorithm:   "argon2id",
				Salt:        []byte("kdf-salt"),
				TimeCost:    3,
				MemoryKiB:   64 * 1024,
				Parallelism: 4,
				KeyLength:   32,
			},
		},
	}
}

func newTestService(repository Repository) *Service {
	return NewService(
		repository,
		fakePasswordHasher{},
		fakeIDGenerator{id: "user-id-1"},
		&fakeTokenIssuer{
			token: token.AccessToken{
				Value:     "access-token",
				ExpiresAt: time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC),
			},
		},
	)
}

func TestServiceRegisterCreatesUserWithPasswordHashVaultMetadataAndAccessToken(t *testing.T) {
	repository := &fakeRepository{}
	tokenIssuer := &fakeTokenIssuer{
		token: token.AccessToken{
			Value:     "access-token",
			ExpiresAt: time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC),
		},
	}
	service := NewService(
		repository,
		fakePasswordHasher{},
		fakeIDGenerator{id: "user-id-1"},
		tokenIssuer,
	)

	result, err := service.Register(context.Background(), Input{
		Login:         "  user@example.com  ",
		LoginPassword: "login-password",
		VaultKey:      validInput().VaultKey,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if result.UserID != "user-id-1" {
		t.Fatalf("UserID = %q, want %q", result.UserID, "user-id-1")
	}

	if result.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want access-token", result.AccessToken)
	}

	if !result.AccessTokenExpiresAt.Equal(time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)) {
		t.Fatalf("AccessTokenExpiresAt = %s, want fixed expires at", result.AccessTokenExpiresAt)
	}

	if string(result.VaultKey.EncryptedVaultKey) != "encrypted-vault-key" {
		t.Fatalf("result EncryptedVaultKey = %q, want encrypted vault key", string(result.VaultKey.EncryptedVaultKey))
	}

	if len(tokenIssuer.calls) != 1 || tokenIssuer.calls[0] != "user-id-1" {
		t.Fatalf("token issuer calls = %v, want user-id-1", tokenIssuer.calls)
	}

	if len(repository.calls) != 1 {
		t.Fatalf("repository calls = %d, want 1", len(repository.calls))
	}

	params := repository.calls[0]

	if params.UserID != "user-id-1" {
		t.Fatalf("UserID = %q, want %q", params.UserID, "user-id-1")
	}

	if params.Login != "user@example.com" {
		t.Fatalf("Login = %q, want %q", params.Login, "user@example.com")
	}

	if params.PasswordHash != "hashed:login-password" {
		t.Fatalf("PasswordHash = %q, want hashed password", params.PasswordHash)
	}

	if params.PasswordHash == "login-password" {
		t.Fatalf("PasswordHash stores plain login password")
	}

	if string(params.VaultKey.EncryptedVaultKey) != "encrypted-vault-key" {
		t.Fatalf("EncryptedVaultKey = %q, want encrypted vault key", string(params.VaultKey.EncryptedVaultKey))
	}

	if params.VaultKey.KDFParams.MemoryKiB != 64*1024 {
		t.Fatalf("MemoryKiB = %d, want %d", params.VaultKey.KDFParams.MemoryKiB, 64*1024)
	}
}

func TestServiceRegisterReturnsErrorForDuplicateLogin(t *testing.T) {
	repository := &fakeRepository{
		createFunc: func(context.Context, CreateUserWithVaultParams) error {
			return ErrLoginAlreadyExists
		},
	}
	service := newTestService(repository)

	_, err := service.Register(context.Background(), validInput())
	if !errors.Is(err, ErrLoginAlreadyExists) {
		t.Fatalf("Register() error = %v, want ErrLoginAlreadyExists", err)
	}
}

func TestServiceRegisterDoesNotCallRepositoryWhenPasswordHashFails(t *testing.T) {
	hashErr := errors.New("hash failed")
	repository := &fakeRepository{}
	service := NewService(
		repository,
		fakePasswordHasher{hashFunc: func(string) (string, error) {
			return "", hashErr
		}},
		fakeIDGenerator{id: "user-id-1"},
		&fakeTokenIssuer{},
	)

	_, err := service.Register(context.Background(), validInput())
	if !errors.Is(err, hashErr) {
		t.Fatalf("Register() error = %v, want hash error", err)
	}

	if len(repository.calls) != 0 {
		t.Fatalf("repository calls = %d, want 0", len(repository.calls))
	}
}

func TestServiceRegisterDoesNotCallRepositoryWhenIDGenerationFails(t *testing.T) {
	idErr := errors.New("id generation failed")
	repository := &fakeRepository{}
	service := NewService(
		repository,
		fakePasswordHasher{},
		fakeIDGenerator{err: idErr},
		&fakeTokenIssuer{},
	)

	_, err := service.Register(context.Background(), validInput())
	if !errors.Is(err, idErr) {
		t.Fatalf("Register() error = %v, want id generation error", err)
	}

	if len(repository.calls) != 0 {
		t.Fatalf("repository calls = %d, want 0", len(repository.calls))
	}
}

func TestServiceRegisterReturnsErrorWhenTokenIssuerIsMissing(t *testing.T) {
	repository := &fakeRepository{}
	service := NewService(
		repository,
		fakePasswordHasher{},
		fakeIDGenerator{id: "user-id-1"},
		nil,
	)

	_, err := service.Register(context.Background(), validInput())
	if err == nil {
		t.Fatalf("Register() error = nil, want error")
	}

	if len(repository.calls) != 0 {
		t.Fatalf("repository calls = %d, want 0", len(repository.calls))
	}
}

func TestServiceRegisterReturnsErrorWhenTokenIssueFails(t *testing.T) {
	issueErr := errors.New("issue failed")
	repository := &fakeRepository{}
	service := NewService(
		repository,
		fakePasswordHasher{},
		fakeIDGenerator{id: "user-id-1"},
		&fakeTokenIssuer{err: issueErr},
	)

	_, err := service.Register(context.Background(), validInput())
	if !errors.Is(err, issueErr) {
		t.Fatalf("Register() error = %v, want issue error", err)
	}

	if len(repository.calls) != 1 {
		t.Fatalf("repository calls = %d, want 1", len(repository.calls))
	}
}

func TestServiceRegisterReturnsErrorForInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input Input
	}{
		{
			name: "empty login",
			input: func() Input {
				input := validInput()
				input.Login = " "
				return input
			}(),
		},
		{
			name: "empty login password",
			input: func() Input {
				input := validInput()
				input.LoginPassword = ""
				return input
			}(),
		},
		{
			name: "empty encrypted vault key",
			input: func() Input {
				input := validInput()
				input.VaultKey.EncryptedVaultKey = nil
				return input
			}(),
		},
		{
			name: "empty vault key nonce",
			input: func() Input {
				input := validInput()
				input.VaultKey.Nonce = nil
				return input
			}(),
		},
		{
			name: "empty encryption algorithm",
			input: func() Input {
				input := validInput()
				input.VaultKey.EncryptionAlg = " "
				return input
			}(),
		},
		{
			name: "empty kdf salt",
			input: func() Input {
				input := validInput()
				input.VaultKey.KDFParams.Salt = nil
				return input
			}(),
		},
		{
			name: "zero kdf memory",
			input: func() Input {
				input := validInput()
				input.VaultKey.KDFParams.MemoryKiB = 0
				return input
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := &fakeRepository{}
			service := newTestService(repository)

			_, err := service.Register(context.Background(), tt.input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Register() error = %v, want ErrInvalidInput", err)
			}

			if len(repository.calls) != 0 {
				t.Fatalf("repository calls = %d, want 0", len(repository.calls))
			}
		})
	}
}
