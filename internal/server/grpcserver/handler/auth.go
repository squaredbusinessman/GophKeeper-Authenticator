// Package handler содержит gRPC-обработчики серверного API
package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/login"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/register"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RegisterUseCase описывает use case регистрации пользователя
type RegisterUseCase interface {
	Register(context.Context, register.Input) (register.Result, error)
}

// LoginUseCase описывает use case входа пользователя
type LoginUseCase interface {
	Login(context.Context, login.Input) (login.Result, error)
}

// AuthHandler обрабатывает запросы сервиса аутентификации
type AuthHandler struct {
	gophkeeperv1.UnimplementedAuthServiceServer

	registerUseCase RegisterUseCase
	loginUseCase    LoginUseCase
}

// NewAuthHandler создает обработчик сервиса аутентификации
func NewAuthHandler(registerUseCase RegisterUseCase, loginUseCase LoginUseCase) *AuthHandler {
	return &AuthHandler{
		registerUseCase: registerUseCase,
		loginUseCase:    loginUseCase,
	}
}

// Register создает нового пользователя через gRPC API
func (h *AuthHandler) Register(ctx context.Context, req *gophkeeperv1.RegisterRequest) (*gophkeeperv1.RegisterResponse, error) {
	input, err := registerInputFromProto(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if h.registerUseCase == nil {
		return nil, status.Error(codes.InvalidArgument, "register use case is not configured")
	}

	if _, err = h.registerUseCase.Register(ctx, input); err != nil {
		return nil, registerStatusError(err)
	}

	return &gophkeeperv1.RegisterResponse{
		VaultKey: req.GetVaultKey(),
	}, nil
}

// Login выполняет вход пользователя через gRPC API
func (h *AuthHandler) Login(ctx context.Context, req *gophkeeperv1.LoginRequest) (*gophkeeperv1.LoginResponse, error) {
	input, err := loginInputFromProto(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if h.loginUseCase == nil {
		return nil, status.Error(codes.InvalidArgument, "login use case is not configured")
	}

	result, err := h.loginUseCase.Login(ctx, input)
	if err != nil {
		return nil, loginStatusError(err)
	}

	return &gophkeeperv1.LoginResponse{
		AccessToken:          result.AccessToken,
		AccessTokenExpiresAt: timestamppb.New(result.AccessTokenExpiresAt),
		VaultKey:             vaultKeyToProto(result.VaultKey),
	}, nil
}

func registerInputFromProto(req *gophkeeperv1.RegisterRequest) (register.Input, error) {
	if req == nil {
		return register.Input{}, fmt.Errorf("register request is required")
	}

	if strings.TrimSpace(req.GetLogin()) == "" {
		return register.Input{}, fmt.Errorf("login is required")
	}

	if req.GetLoginPassword() == "" {
		return register.Input{}, fmt.Errorf("password is required")
	}

	vaultKey := req.GetVaultKey()
	if vaultKey == nil {
		return register.Input{}, fmt.Errorf("vault key is required")
	}

	kdfParams := vaultKey.GetKdfParams()
	if kdfParams == nil {
		return register.Input{}, fmt.Errorf("kdf params are required")
	}

	input := register.Input{
		Login:         req.GetLogin(),
		LoginPassword: req.GetLoginPassword(),
		VaultKey: register.VaultKeyEnvelope{
			EncryptedVaultKey: vaultKey.GetEncryptedVaultKey(),
			Nonce:             vaultKey.GetNonce(),
			EncryptionAlg:     vaultKey.GetEncryptionAlg(),
			KDFParams: register.KDFParams{
				Algorithm:   kdfParams.GetAlgorithm(),
				Salt:        kdfParams.GetSalt(),
				TimeCost:    kdfParams.GetTimeCost(),
				MemoryKiB:   kdfParams.GetMemoryKib(),
				Parallelism: kdfParams.GetParallelism(),
				KeyLength:   kdfParams.GetKeyLength(),
			},
		},
	}

	if err := input.VaultKey.Validate(); err != nil {
		return register.Input{}, err
	}

	return input, nil
}

func loginInputFromProto(req *gophkeeperv1.LoginRequest) (login.Input, error) {
	if req == nil {
		return login.Input{}, fmt.Errorf("login request is required")
	}

	if strings.TrimSpace(req.GetLogin()) == "" {
		return login.Input{}, fmt.Errorf("login is required")
	}

	if req.GetLoginPassword() == "" {
		return login.Input{}, fmt.Errorf("password is required")
	}

	return login.Input{
		Login:         req.GetLogin(),
		LoginPassword: req.GetLoginPassword(),
	}, nil
}

func vaultKeyToProto(vaultKey login.VaultKeyEnvelope) *gophkeeperv1.VaultKeyEnvelope {
	return &gophkeeperv1.VaultKeyEnvelope{
		EncryptedVaultKey: vaultKey.EncryptedVaultKey,
		Nonce:             vaultKey.Nonce,
		EncryptionAlg:     vaultKey.EncryptionAlg,
		KdfParams: &gophkeeperv1.KDFParams{
			Algorithm:   vaultKey.KDFParams.Algorithm,
			Salt:        vaultKey.KDFParams.Salt,
			TimeCost:    vaultKey.KDFParams.TimeCost,
			MemoryKib:   vaultKey.KDFParams.MemoryKiB,
			Parallelism: vaultKey.KDFParams.Parallelism,
			KeyLength:   vaultKey.KDFParams.KeyLength,
		},
	}
}

func loginStatusError(err error) error {
	switch {
	case errors.Is(err, login.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, login.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, err.Error())
	default:
		return status.Error(codes.Internal, "login failed")
	}
}

func registerStatusError(err error) error {
	switch {
	case errors.Is(err, register.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, register.ErrLoginAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	default:
		return status.Error(codes.Internal, "register failed")
	}
}
