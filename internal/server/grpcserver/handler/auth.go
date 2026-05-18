// Package handler содержит gRPC-обработчики серверного API
package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/register"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterUseCase описывает use case регистрации пользователя
type RegisterUseCase interface {
	Register(context.Context, register.Input) (register.Result, error)
}

// AuthHandler обрабатывает запросы сервиса аутентификации
type AuthHandler struct {
	gophkeeperv1.UnimplementedAuthServiceServer

	registerUseCase RegisterUseCase
}

// NewAuthHandler создает обработчик сервиса аутентификации
func NewAuthHandler(registerUseCase RegisterUseCase) *AuthHandler {
	return &AuthHandler{
		registerUseCase: registerUseCase,
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
