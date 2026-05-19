package core

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/crypto/vaultkey"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeAuthClient struct {
	registerFunc func(context.Context, *gophkeeperv1.RegisterRequest, ...grpc.CallOption) (*gophkeeperv1.RegisterResponse, error)
	loginFunc    func(context.Context, *gophkeeperv1.LoginRequest, ...grpc.CallOption) (*gophkeeperv1.LoginResponse, error)

	registerCalls []*gophkeeperv1.RegisterRequest
	loginCalls    []*gophkeeperv1.LoginRequest
}

func (c *fakeAuthClient) Register(ctx context.Context, req *gophkeeperv1.RegisterRequest, opts ...grpc.CallOption) (*gophkeeperv1.RegisterResponse, error) {
	c.registerCalls = append(c.registerCalls, req)
	if c.registerFunc != nil {
		return c.registerFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected register call")
}

func (c *fakeAuthClient) Login(ctx context.Context, req *gophkeeperv1.LoginRequest, opts ...grpc.CallOption) (*gophkeeperv1.LoginResponse, error) {
	c.loginCalls = append(c.loginCalls, req)
	if c.loginFunc != nil {
		return c.loginFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected login call")
}

type fakeTokenStore struct {
	saveFunc func(context.Context, TokenState) error
	saves    []TokenState
}

func (s *fakeTokenStore) Save(ctx context.Context, state TokenState) error {
	s.saves = append(s.saves, state)
	if s.saveFunc != nil {
		return s.saveFunc(ctx, state)
	}

	return nil
}

func TestAuthServiceRegisterCreatesEncryptedVaultKeyAndStoresToken(t *testing.T) {
	expiresAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)

	authClient := &fakeAuthClient{
		registerFunc: func(_ context.Context, req *gophkeeperv1.RegisterRequest, _ ...grpc.CallOption) (*gophkeeperv1.RegisterResponse, error) {
			return &gophkeeperv1.RegisterResponse{
				AccessToken:          "access-token",
				AccessTokenExpiresAt: timestamppb.New(expiresAt),
				VaultKey:             req.GetVaultKey(),
			}, nil
		},
	}
	tokenStore := &fakeTokenStore{}
	service := NewAuthService(authClient, tokenStore)

	session, err := service.Register(context.Background(), RegisterInput{
		Login:          "user@example.com",
		LoginPassword:  "login-password",
		MasterPassword: "master-password",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if len(authClient.registerCalls) != 1 {
		t.Fatalf("Register() calls = %d, want 1", len(authClient.registerCalls))
	}

	request := authClient.registerCalls[0]
	if request.GetLogin() != "user@example.com" {
		t.Fatalf("request login = %q, want original login", request.GetLogin())
	}

	if request.GetLoginPassword() != "login-password" {
		t.Fatalf("request login password = %q, want original login password", request.GetLoginPassword())
	}

	if request.GetVaultKey() == nil {
		t.Fatalf("request vault key = nil")
	}

	if len(request.GetVaultKey().GetEncryptedVaultKey()) == 0 {
		t.Fatalf("request encrypted vault key is empty")
	}

	if request.GetVaultKey().GetEncryptionAlg() != vaultkey.EncryptionAlgorithm {
		t.Fatalf("encryption alg = %q, want %q", request.GetVaultKey().GetEncryptionAlg(), vaultkey.EncryptionAlgorithm)
	}

	decryptedVaultKey, err := vaultkey.Decrypt("master-password", vaultKeyEnvelopeFromProto(request.GetVaultKey()))
	if err != nil {
		t.Fatalf("decrypt request vault key: %v", err)
	}

	if !bytes.Equal(decryptedVaultKey, session.VaultKey) {
		t.Fatalf("session vault key does not match encrypted request vault key")
	}

	if len(session.VaultKey) != vaultkey.KeyLength {
		t.Fatalf("session vault key length = %d, want %d", len(session.VaultKey), vaultkey.KeyLength)
	}

	if session.AccessToken != "access-token" {
		t.Fatalf("session access token = %q, want access-token", session.AccessToken)
	}

	if !session.AccessTokenExpiresAt.Equal(expiresAt) {
		t.Fatalf("session expires at = %s, want %s", session.AccessTokenExpiresAt, expiresAt)
	}

	if len(tokenStore.saves) != 1 {
		t.Fatalf("token store saves = %d, want 1", len(tokenStore.saves))
	}

	if tokenStore.saves[0].AccessToken != "access-token" {
		t.Fatalf("stored access token = %q, want access-token", tokenStore.saves[0].AccessToken)
	}

	if !tokenStore.saves[0].ExpiresAt.Equal(expiresAt) {
		t.Fatalf("stored expires at = %s, want %s", tokenStore.saves[0].ExpiresAt, expiresAt)
	}
}

func TestAuthServiceLoginDecryptsVaultKeyAndStoresToken(t *testing.T) {
	expiresAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	rawVaultKey := bytes.Repeat([]byte{7}, vaultkey.KeyLength)
	envelope, err := vaultkey.Encrypt("master-password", rawVaultKey)
	if err != nil {
		t.Fatalf("encrypt vault key: %v", err)
	}

	authClient := &fakeAuthClient{
		loginFunc: func(_ context.Context, req *gophkeeperv1.LoginRequest, _ ...grpc.CallOption) (*gophkeeperv1.LoginResponse, error) {
			return &gophkeeperv1.LoginResponse{
				AccessToken:          "access-token",
				AccessTokenExpiresAt: timestamppb.New(expiresAt),
				VaultKey:             vaultKeyEnvelopeToProto(envelope),
			}, nil
		},
	}
	tokenStore := &fakeTokenStore{}
	service := NewAuthService(authClient, tokenStore)

	session, err := service.Login(context.Background(), LoginInput{
		Login:          "user@example.com",
		LoginPassword:  "login-password",
		MasterPassword: "master-password",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if len(authClient.loginCalls) != 1 {
		t.Fatalf("Login() calls = %d, want 1", len(authClient.loginCalls))
	}

	request := authClient.loginCalls[0]
	if request.GetLogin() != "user@example.com" {
		t.Fatalf("request login = %q, want original login", request.GetLogin())
	}

	if request.GetLoginPassword() != "login-password" {
		t.Fatalf("request login password = %q, want original login password", request.GetLoginPassword())
	}

	if !bytes.Equal(session.VaultKey, rawVaultKey) {
		t.Fatalf("session vault key does not match decrypted vault key")
	}

	if session.AccessToken != "access-token" {
		t.Fatalf("session access token = %q, want access-token", session.AccessToken)
	}

	if len(tokenStore.saves) != 1 {
		t.Fatalf("token store saves = %d, want 1", len(tokenStore.saves))
	}
}

func TestAuthServiceLoginReturnsErrorForWrongMasterPasswordAndDoesNotStoreToken(t *testing.T) {
	rawVaultKey := bytes.Repeat([]byte{9}, vaultkey.KeyLength)
	envelope, err := vaultkey.Encrypt("correct-master-password", rawVaultKey)
	if err != nil {
		t.Fatalf("encrypt vault key: %v", err)
	}

	authClient := &fakeAuthClient{
		loginFunc: func(_ context.Context, _ *gophkeeperv1.LoginRequest, _ ...grpc.CallOption) (*gophkeeperv1.LoginResponse, error) {
			return &gophkeeperv1.LoginResponse{
				AccessToken:          "access-token",
				AccessTokenExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
				VaultKey:             vaultKeyEnvelopeToProto(envelope),
			}, nil
		},
	}
	tokenStore := &fakeTokenStore{}
	service := NewAuthService(authClient, tokenStore)

	_, err = service.Login(context.Background(), LoginInput{
		Login:          "user@example.com",
		LoginPassword:  "login-password",
		MasterPassword: "wrong-master-password",
	})
	if err == nil {
		t.Fatalf("Login() error = nil, want error")
	}

	if len(tokenStore.saves) != 0 {
		t.Fatalf("token store saves = %d, want 0", len(tokenStore.saves))
	}
}

func TestAuthServiceRegisterReturnsErrorWhenAccessTokenIsMissing(t *testing.T) {
	authClient := &fakeAuthClient{
		registerFunc: func(_ context.Context, req *gophkeeperv1.RegisterRequest, _ ...grpc.CallOption) (*gophkeeperv1.RegisterResponse, error) {
			return &gophkeeperv1.RegisterResponse{
				AccessTokenExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
				VaultKey:             req.GetVaultKey(),
			}, nil
		},
	}
	tokenStore := &fakeTokenStore{}
	service := NewAuthService(authClient, tokenStore)

	_, err := service.Register(context.Background(), RegisterInput{
		Login:          "user@example.com",
		LoginPassword:  "login-password",
		MasterPassword: "master-password",
	})
	if err == nil {
		t.Fatalf("Register() error = nil, want error")
	}

	if len(tokenStore.saves) != 0 {
		t.Fatalf("token store saves = %d, want 0", len(tokenStore.saves))
	}
}

func TestAuthServiceRegisterReturnsErrorForInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input RegisterInput
	}{
		{
			name: "empty login",
			input: RegisterInput{
				LoginPassword:  "login-password",
				MasterPassword: "master-password",
			},
		},
		{
			name: "empty login password",
			input: RegisterInput{
				Login:          "user@example.com",
				MasterPassword: "master-password",
			},
		},
		{
			name: "empty master password",
			input: RegisterInput{
				Login:         "user@example.com",
				LoginPassword: "login-password",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authClient := &fakeAuthClient{}
			tokenStore := &fakeTokenStore{}
			service := NewAuthService(authClient, tokenStore)

			_, err := service.Register(context.Background(), tt.input)
			if err == nil {
				t.Fatalf("Register() error = nil, want error")
			}

			if len(authClient.registerCalls) != 0 {
				t.Fatalf("Register() calls = %d, want 0", len(authClient.registerCalls))
			}

			if len(tokenStore.saves) != 0 {
				t.Fatalf("token store saves = %d, want 0", len(tokenStore.saves))
			}
		})
	}
}

func TestAuthServiceLoginReturnsErrorForInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input LoginInput
	}{
		{
			name: "empty login",
			input: LoginInput{
				LoginPassword:  "login-password",
				MasterPassword: "master-password",
			},
		},
		{
			name: "empty login password",
			input: LoginInput{
				Login:          "user@example.com",
				MasterPassword: "master-password",
			},
		},
		{
			name: "empty master password",
			input: LoginInput{
				Login:         "user@example.com",
				LoginPassword: "login-password",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authClient := &fakeAuthClient{}
			tokenStore := &fakeTokenStore{}
			service := NewAuthService(authClient, tokenStore)

			_, err := service.Login(context.Background(), tt.input)
			if err == nil {
				t.Fatalf("Login() error = nil, want error")
			}

			if len(authClient.loginCalls) != 0 {
				t.Fatalf("Login() calls = %d, want 0", len(authClient.loginCalls))
			}

			if len(tokenStore.saves) != 0 {
				t.Fatalf("token store saves = %d, want 0", len(tokenStore.saves))
			}
		})
	}
}

func TestAuthServiceReturnsErrorForMissingDependencies(t *testing.T) {
	validRegisterInput := RegisterInput{
		Login:          "user@example.com",
		LoginPassword:  "login-password",
		MasterPassword: "master-password",
	}
	validLoginInput := LoginInput{
		Login:          "user@example.com",
		LoginPassword:  "login-password",
		MasterPassword: "master-password",
	}

	t.Run("register without auth client", func(t *testing.T) {
		service := NewAuthService(nil, &fakeTokenStore{})

		_, err := service.Register(context.Background(), validRegisterInput)
		if err == nil {
			t.Fatalf("Register() error = nil, want error")
		}
	})

	t.Run("register without token store", func(t *testing.T) {
		service := NewAuthService(&fakeAuthClient{}, nil)

		_, err := service.Register(context.Background(), validRegisterInput)
		if err == nil {
			t.Fatalf("Register() error = nil, want error")
		}
	})

	t.Run("login without auth client", func(t *testing.T) {
		service := NewAuthService(nil, &fakeTokenStore{})

		_, err := service.Login(context.Background(), validLoginInput)
		if err == nil {
			t.Fatalf("Login() error = nil, want error")
		}
	})

	t.Run("login without token store", func(t *testing.T) {
		service := NewAuthService(&fakeAuthClient{}, nil)

		_, err := service.Login(context.Background(), validLoginInput)
		if err == nil {
			t.Fatalf("Login() error = nil, want error")
		}
	})
}

func TestAuthServiceReturnsErrorWhenTokenStoreSaveFails(t *testing.T) {
	expiresAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	saveErr := errors.New("save failed")
	authClient := &fakeAuthClient{
		registerFunc: func(_ context.Context, req *gophkeeperv1.RegisterRequest, _ ...grpc.CallOption) (*gophkeeperv1.RegisterResponse, error) {
			return &gophkeeperv1.RegisterResponse{
				AccessToken:          "access-token",
				AccessTokenExpiresAt: timestamppb.New(expiresAt),
				VaultKey:             req.GetVaultKey(),
			}, nil
		},
	}
	tokenStore := &fakeTokenStore{
		saveFunc: func(context.Context, TokenState) error {
			return saveErr
		},
	}
	service := NewAuthService(authClient, tokenStore)

	_, err := service.Register(context.Background(), RegisterInput{
		Login:          "user@example.com",
		LoginPassword:  "login-password",
		MasterPassword: "master-password",
	})
	if err == nil {
		t.Fatalf("Register() error = nil, want error")
	}

	if !errors.Is(err, saveErr) {
		t.Fatalf("Register() error = %v, want save error", err)
	}
}

func TestAuthServiceLoginReturnsErrorWhenVaultKeyIsMissing(t *testing.T) {
	authClient := &fakeAuthClient{
		loginFunc: func(_ context.Context, _ *gophkeeperv1.LoginRequest, _ ...grpc.CallOption) (*gophkeeperv1.LoginResponse, error) {
			return &gophkeeperv1.LoginResponse{
				AccessToken:          "access-token",
				AccessTokenExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
			}, nil
		},
	}
	tokenStore := &fakeTokenStore{}
	service := NewAuthService(authClient, tokenStore)

	_, err := service.Login(context.Background(), LoginInput{
		Login:          "user@example.com",
		LoginPassword:  "login-password",
		MasterPassword: "master-password",
	})
	if err == nil {
		t.Fatalf("Login() error = nil, want error")
	}

	if len(tokenStore.saves) != 0 {
		t.Fatalf("token store saves = %d, want 0", len(tokenStore.saves))
	}
}
