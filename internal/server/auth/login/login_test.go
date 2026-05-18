package login

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/token"
)

type fakeRepository struct {
	user   User
	err    error
	logins []string
}

func (r *fakeRepository) FindUserByLogin(ctx context.Context, login string) (User, error) {
	r.logins = append(r.logins, login)
	if r.err != nil {
		return User{}, r.err
	}

	return r.user, nil
}

type fakePasswordVerifier struct {
	ok        bool
	err       error
	passwords []string
	hashes    []string
}

func (v *fakePasswordVerifier) Verify(password, hash string) (bool, error) {
	v.passwords = append(v.passwords, password)
	v.hashes = append(v.hashes, hash)

	if v.err != nil {
		return false, v.err
	}

	return v.ok, nil
}

type fakeTokenIssuer struct {
	token   token.AccessToken
	err     error
	userIDs []string
}

func (i *fakeTokenIssuer) Issue(userID string) (token.AccessToken, error) {
	i.userIDs = append(i.userIDs, userID)
	if i.err != nil {
		return token.AccessToken{}, i.err
	}

	return i.token, nil
}

func validVaultKey() VaultKeyEnvelope {
	return VaultKeyEnvelope{
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
	}
}

func validUser() User {
	return User{
		ID:           "user-id-1",
		Login:        "user@example.com",
		PasswordHash: "$argon2id$hash",
		VaultKey:     validVaultKey(),
	}
}

func TestServiceLoginReturnsAccessTokenAndVaultMetadata(t *testing.T) {
	expiresAt := time.Date(2026, 5, 18, 12, 5, 0, 0, time.UTC)
	repository := &fakeRepository{user: validUser()}
	verifier := &fakePasswordVerifier{ok: true}
	issuer := &fakeTokenIssuer{
		token: token.AccessToken{
			Value:     "access-token",
			ExpiresAt: expiresAt,
		},
	}
	service := NewService(repository, verifier, issuer)

	result, err := service.Login(context.Background(), Input{
		Login:         "  user@example.com  ",
		LoginPassword: "login-password",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if result.UserID != "user-id-1" {
		t.Fatalf("UserID = %q, want %q", result.UserID, "user-id-1")
	}

	if result.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want %q", result.AccessToken, "access-token")
	}

	if !result.AccessTokenExpiresAt.Equal(expiresAt) {
		t.Fatalf("AccessTokenExpiresAt = %s, want %s", result.AccessTokenExpiresAt, expiresAt)
	}

	if string(result.VaultKey.EncryptedVaultKey) != "encrypted-vault-key" {
		t.Fatalf("EncryptedVaultKey = %q, want original encrypted vault key", string(result.VaultKey.EncryptedVaultKey))
	}

	if len(repository.logins) != 1 || repository.logins[0] != "user@example.com" {
		t.Fatalf("repository logins = %v, want trimmed login", repository.logins)
	}

	if len(verifier.passwords) != 1 || verifier.passwords[0] != "login-password" {
		t.Fatalf("verifier passwords = %v, want original login password", verifier.passwords)
	}

	if len(verifier.hashes) != 1 || verifier.hashes[0] != "$argon2id$hash" {
		t.Fatalf("verifier hashes = %v, want stored password hash", verifier.hashes)
	}

	if len(issuer.userIDs) != 1 || issuer.userIDs[0] != "user-id-1" {
		t.Fatalf("issuer user ids = %v, want user id", issuer.userIDs)
	}
}

func TestServiceLoginReturnsInvalidCredentialsWhenUserNotFound(t *testing.T) {
	repository := &fakeRepository{err: ErrUserNotFound}
	verifier := &fakePasswordVerifier{ok: true}
	issuer := &fakeTokenIssuer{}
	service := NewService(repository, verifier, issuer)

	_, err := service.Login(context.Background(), Input{
		Login:         "user@example.com",
		LoginPassword: "login-password",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
	}

	if len(verifier.passwords) != 0 {
		t.Fatalf("verifier calls = %d, want 0", len(verifier.passwords))
	}

	if len(issuer.userIDs) != 0 {
		t.Fatalf("issuer calls = %d, want 0", len(issuer.userIDs))
	}
}

func TestServiceLoginReturnsInvalidCredentialsForWrongPassword(t *testing.T) {
	repository := &fakeRepository{user: validUser()}
	verifier := &fakePasswordVerifier{ok: false}
	issuer := &fakeTokenIssuer{}
	service := NewService(repository, verifier, issuer)

	_, err := service.Login(context.Background(), Input{
		Login:         "user@example.com",
		LoginPassword: "wrong-password",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
	}

	if len(issuer.userIDs) != 0 {
		t.Fatalf("issuer calls = %d, want 0", len(issuer.userIDs))
	}
}

func TestServiceLoginReturnsErrorForInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input Input
	}{
		{
			name: "empty login",
			input: Input{
				Login:         " ",
				LoginPassword: "login-password",
			},
		},
		{
			name: "empty login password",
			input: Input{
				Login:         "user@example.com",
				LoginPassword: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := &fakeRepository{user: validUser()}
			verifier := &fakePasswordVerifier{ok: true}
			issuer := &fakeTokenIssuer{}
			service := NewService(repository, verifier, issuer)

			_, err := service.Login(context.Background(), tt.input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Login() error = %v, want ErrInvalidInput", err)
			}

			if len(repository.logins) != 0 {
				t.Fatalf("repository calls = %d, want 0", len(repository.logins))
			}
		})
	}
}

func TestServiceLoginReturnsErrorWhenPasswordVerifierFails(t *testing.T) {
	verifyErr := errors.New("verify failed")
	repository := &fakeRepository{user: validUser()}
	verifier := &fakePasswordVerifier{err: verifyErr}
	issuer := &fakeTokenIssuer{}
	service := NewService(repository, verifier, issuer)

	_, err := service.Login(context.Background(), Input{
		Login:         "user@example.com",
		LoginPassword: "login-password",
	})
	if !errors.Is(err, verifyErr) {
		t.Fatalf("Login() error = %v, want verifier error", err)
	}

	if len(issuer.userIDs) != 0 {
		t.Fatalf("issuer calls = %d, want 0", len(issuer.userIDs))
	}
}

func TestServiceLoginReturnsErrorWhenTokenIssuerFails(t *testing.T) {
	issuerErr := errors.New("issue token failed")
	repository := &fakeRepository{user: validUser()}
	verifier := &fakePasswordVerifier{ok: true}
	issuer := &fakeTokenIssuer{err: issuerErr}
	service := NewService(repository, verifier, issuer)

	_, err := service.Login(context.Background(), Input{
		Login:         "user@example.com",
		LoginPassword: "login-password",
	})
	if !errors.Is(err, issuerErr) {
		t.Fatalf("Login() error = %v, want issuer error", err)
	}
}
