package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/login"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/register"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeRegisterUseCase struct {
	result register.Result
	err    error
	calls  []register.Input
}

func (u *fakeRegisterUseCase) Register(ctx context.Context, input register.Input) (register.Result, error) {
	u.calls = append(u.calls, input)
	if u.err != nil {
		return register.Result{}, u.err
	}

	return u.result, nil
}

type fakeLoginUseCase struct {
	result login.Result
	err    error
	calls  []login.Input
}

func (u *fakeLoginUseCase) Login(ctx context.Context, input login.Input) (login.Result, error) {
	u.calls = append(u.calls, input)
	if u.err != nil {
		return login.Result{}, u.err
	}

	return u.result, nil
}

func validRegisterRequest() *gophkeeperv1.RegisterRequest {
	return &gophkeeperv1.RegisterRequest{
		Login:         "user@example.com",
		LoginPassword: "login-password",
		VaultKey: &gophkeeperv1.VaultKeyEnvelope{
			EncryptedVaultKey: []byte("encrypted-vault-key"),
			Nonce:             []byte("vault-key-nonce"),
			EncryptionAlg:     "xchacha20poly1305",
			KdfParams: &gophkeeperv1.KDFParams{
				Algorithm:   "argon2id",
				Salt:        []byte("kdf-salt"),
				TimeCost:    3,
				MemoryKib:   64 * 1024,
				Parallelism: 4,
				KeyLength:   32,
			},
		},
	}
}

func validLoginRequest() *gophkeeperv1.LoginRequest {
	return &gophkeeperv1.LoginRequest{
		Login:         "user@example.com",
		LoginPassword: "login-password",
	}
}

func validLoginResult() login.Result {
	return login.Result{
		UserID:               "user-id-1",
		AccessToken:          "access-token",
		AccessTokenExpiresAt: time.Date(2026, 5, 18, 12, 5, 0, 0, time.UTC),
		VaultKey: login.VaultKeyEnvelope{
			EncryptedVaultKey: []byte("encrypted-vault-key"),
			Nonce:             []byte("vault-key-nonce"),
			EncryptionAlg:     "xchacha20poly1305",
			KDFParams: login.KDFParams{
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

func TestAuthHandlerRegisterCallsUseCaseAndReturnsVaultKey(t *testing.T) {
	useCase := &fakeRegisterUseCase{
		result: register.Result{UserID: "user-id-1"},
	}
	handler := NewAuthHandler(useCase, nil)

	response, err := handler.Register(context.Background(), validRegisterRequest())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if response == nil {
		t.Fatalf("Register() response = nil")
	}

	if response.VaultKey == nil {
		t.Fatalf("Register() VaultKey = nil")
	}

	if string(response.VaultKey.EncryptedVaultKey) != "encrypted-vault-key" {
		t.Fatalf("EncryptedVaultKey = %q, want original encrypted vault key", string(response.VaultKey.EncryptedVaultKey))
	}

	if len(useCase.calls) != 1 {
		t.Fatalf("use case calls = %d, want 1", len(useCase.calls))
	}

	input := useCase.calls[0]

	if input.Login != "user@example.com" {
		t.Fatalf("input Login = %q, want %q", input.Login, "user@example.com")
	}

	if input.LoginPassword != "login-password" {
		t.Fatalf("input LoginPassword = %q, want original login password", input.LoginPassword)
	}

	if string(input.VaultKey.EncryptedVaultKey) != "encrypted-vault-key" {
		t.Fatalf("input EncryptedVaultKey = %q, want original encrypted vault key", string(input.VaultKey.EncryptedVaultKey))
	}

	if input.VaultKey.KDFParams.MemoryKiB != 64*1024 {
		t.Fatalf("input KDF memory = %d, want %d", input.VaultKey.KDFParams.MemoryKiB, 64*1024)
	}
}

func TestAuthHandlerRegisterReturnsInvalidArgumentForInvalidRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *gophkeeperv1.RegisterRequest
	}{
		{
			name:    "nil request",
			request: nil,
		},
		{
			name: "empty login",
			request: func() *gophkeeperv1.RegisterRequest {
				request := validRegisterRequest()
				request.Login = " "
				return request
			}(),
		},
		{
			name: "empty login password",
			request: func() *gophkeeperv1.RegisterRequest {
				request := validRegisterRequest()
				request.LoginPassword = ""
				return request
			}(),
		},
		{
			name: "nil vault key",
			request: func() *gophkeeperv1.RegisterRequest {
				request := validRegisterRequest()
				request.VaultKey = nil
				return request
			}(),
		},
		{
			name: "nil kdf params",
			request: func() *gophkeeperv1.RegisterRequest {
				request := validRegisterRequest()
				request.VaultKey.KdfParams = nil
				return request
			}(),
		},
		{
			name: "empty encrypted vault key",
			request: func() *gophkeeperv1.RegisterRequest {
				request := validRegisterRequest()
				request.VaultKey.EncryptedVaultKey = nil
				return request
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCase := &fakeRegisterUseCase{}
			handler := NewAuthHandler(useCase, nil)

			_, err := handler.Register(context.Background(), tt.request)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Register() code = %s, want %s, err = %v", status.Code(err), codes.InvalidArgument, err)
			}

			if len(useCase.calls) != 0 {
				t.Fatalf("use case calls = %d, want 0", len(useCase.calls))
			}
		})
	}
}

func TestAuthHandlerRegisterMapsUseCaseErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{
			name: "invalid input",
			err:  register.ErrInvalidInput,
			code: codes.InvalidArgument,
		},
		{
			name: "duplicate login",
			err:  register.ErrLoginAlreadyExists,
			code: codes.AlreadyExists,
		},
		{
			name: "internal error",
			err:  errors.New("database failed"),
			code: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCase := &fakeRegisterUseCase{err: tt.err}
			handler := NewAuthHandler(useCase, nil)

			_, err := handler.Register(context.Background(), validRegisterRequest())
			if status.Code(err) != tt.code {
				t.Fatalf("Register() code = %s, want %s, err = %v", status.Code(err), tt.code, err)
			}
		})
	}
}

func TestAuthHandlerLoginCallsUseCaseAndReturnsTokenWithVaultKey(t *testing.T) {
	useCase := &fakeLoginUseCase{result: validLoginResult()}
	handler := NewAuthHandler(nil, useCase)

	response, err := handler.Login(context.Background(), validLoginRequest())
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if response == nil {
		t.Fatalf("Login() response = nil")
	}

	if response.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want %q", response.AccessToken, "access-token")
	}

	if response.AccessTokenExpiresAt == nil {
		t.Fatalf("AccessTokenExpiresAt = nil")
	}

	if !response.AccessTokenExpiresAt.AsTime().Equal(validLoginResult().AccessTokenExpiresAt) {
		t.Fatalf("AccessTokenExpiresAt = %s, want %s", response.AccessTokenExpiresAt.AsTime(), validLoginResult().AccessTokenExpiresAt)
	}

	if response.VaultKey == nil {
		t.Fatalf("VaultKey = nil")
	}

	if string(response.VaultKey.EncryptedVaultKey) != "encrypted-vault-key" {
		t.Fatalf("EncryptedVaultKey = %q, want original encrypted vault key", string(response.VaultKey.EncryptedVaultKey))
	}

	if response.VaultKey.KdfParams.GetMemoryKib() != 64*1024 {
		t.Fatalf("KDF memory = %d, want %d", response.VaultKey.KdfParams.GetMemoryKib(), 64*1024)
	}

	if len(useCase.calls) != 1 {
		t.Fatalf("use case calls = %d, want 1", len(useCase.calls))
	}

	input := useCase.calls[0]

	if input.Login != "user@example.com" {
		t.Fatalf("input Login = %q, want %q", input.Login, "user@example.com")
	}

	if input.LoginPassword != "login-password" {
		t.Fatalf("input LoginPassword = %q, want original login password", input.LoginPassword)
	}
}

func TestAuthHandlerLoginReturnsInvalidArgumentForInvalidRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *gophkeeperv1.LoginRequest
	}{
		{
			name:    "nil request",
			request: nil,
		},
		{
			name: "empty login",
			request: func() *gophkeeperv1.LoginRequest {
				request := validLoginRequest()
				request.Login = " "
				return request
			}(),
		},
		{
			name: "empty login password",
			request: func() *gophkeeperv1.LoginRequest {
				request := validLoginRequest()
				request.LoginPassword = ""
				return request
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCase := &fakeLoginUseCase{result: validLoginResult()}
			handler := NewAuthHandler(nil, useCase)

			_, err := handler.Login(context.Background(), tt.request)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Login() code = %s, want %s, err = %v", status.Code(err), codes.InvalidArgument, err)
			}

			if len(useCase.calls) != 0 {
				t.Fatalf("use case calls = %d, want 0", len(useCase.calls))
			}
		})
	}
}

func TestAuthHandlerLoginMapsUseCaseErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{
			name: "invalid input",
			err:  login.ErrInvalidInput,
			code: codes.InvalidArgument,
		},
		{
			name: "invalid credentials",
			err:  login.ErrInvalidCredentials,
			code: codes.Unauthenticated,
		},
		{
			name: "internal error",
			err:  errors.New("database failed"),
			code: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCase := &fakeLoginUseCase{err: tt.err}
			handler := NewAuthHandler(nil, useCase)

			_, err := handler.Login(context.Background(), validLoginRequest())
			if status.Code(err) != tt.code {
				t.Fatalf("Login() code = %s, want %s, err = %v", status.Code(err), tt.code, err)
			}
		})
	}
}
