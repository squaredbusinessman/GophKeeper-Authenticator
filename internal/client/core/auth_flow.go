package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/crypto/vaultkey"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuthServiceClient описывает gRPC-клиент auth API, который нужен client core
type AuthServiceClient interface {
	Register(context.Context, *gophkeeperv1.RegisterRequest, ...grpc.CallOption) (*gophkeeperv1.RegisterResponse, error)
	Login(context.Context, *gophkeeperv1.LoginRequest, ...grpc.CallOption) (*gophkeeperv1.LoginResponse, error)
}

// TokenStore сохраняет состояние access token без привязки core к файлам или UI
type TokenStore interface {
	Save(context.Context, TokenState) error
}

// TokenState содержит состояние access token клиентской сессии
type TokenState struct {
	AccessToken string
	ExpiresAt   time.Time
}

// RegisterInput содержит данные для регистрации из любого UI-слоя
type RegisterInput struct {
	Login          string
	LoginPassword  string
	MasterPassword string
}

// LoginInput содержит данные для входа из любого UI-слоя
type LoginInput struct {
	Login          string
	LoginPassword  string
	MasterPassword string
}

// Session содержит открытую клиентскую сессию и расшифрованный vault key
type Session struct {
	AccessToken          string
	AccessTokenExpiresAt time.Time
	VaultKey             []byte
}

type authResponse struct {
	AccessToken string
	ExpiresAt   *timestamppb.Timestamp
}

// AuthService выполняет register/login flow без UI-логики
type AuthService struct {
	authClient AuthServiceClient
	tokenStore TokenStore
}

// NewAuthService создает client auth core
func NewAuthService(authClient AuthServiceClient, tokenStore TokenStore) *AuthService {
	return &AuthService{
		authClient: authClient,
		tokenStore: tokenStore,
	}
}

// Register регистрирует пользователя, создает vault key и сохраняет access token
func (a *AuthService) Register(ctx context.Context, input RegisterInput) (Session, error) {
	if err := input.validate(); err != nil {
		return Session{}, err
	}

	if a.authClient == nil {
		return Session{}, fmt.Errorf("auth client is required")
	}

	if a.tokenStore == nil {
		return Session{}, fmt.Errorf("token store is required")
	}

	rawVaultKey, err := vaultkey.Generate()
	if err != nil {
		return Session{}, fmt.Errorf("could not generate vault key: %w", err)
	}

	envelope, err := vaultkey.Encrypt(input.MasterPassword, rawVaultKey)
	if err != nil {
		return Session{}, fmt.Errorf("could not encrypt vault key: %w", err)
	}

	response, err := a.authClient.Register(ctx, gophkeeperv1.RegisterRequest_builder{
		Login:         strings.TrimSpace(input.Login),
		LoginPassword: input.LoginPassword,
		VaultKey:      vaultKeyEnvelopeToProto(envelope),
	}.Build())
	if err != nil {
		return Session{}, fmt.Errorf("could not register user: %w", err)
	}

	session, err := sessionFromAuthResponse(authResponse{
		AccessToken: response.GetAccessToken(),
		ExpiresAt:   response.GetAccessTokenExpiresAt(),
	}, rawVaultKey)
	if err != nil {
		return Session{}, err
	}

	if err = a.tokenStore.Save(ctx, TokenState{
		AccessToken: session.AccessToken,
		ExpiresAt:   session.AccessTokenExpiresAt,
	}); err != nil {
		return Session{}, fmt.Errorf("could not save token state: %w", err)
	}

	return session, nil
}

// Login выполняет вход, расшифровывает vault key и сохраняет access token
func (a *AuthService) Login(ctx context.Context, input LoginInput) (Session, error) {
	if err := input.validate(); err != nil {
		return Session{}, err
	}

	if a.authClient == nil {
		return Session{}, fmt.Errorf("auth client is required")
	}

	if a.tokenStore == nil {
		return Session{}, fmt.Errorf("token store is required")
	}

	response, err := a.authClient.Login(ctx, gophkeeperv1.LoginRequest_builder{
		Login:         strings.TrimSpace(input.Login),
		LoginPassword: input.LoginPassword,
	}.Build())
	if err != nil {
		return Session{}, fmt.Errorf("could not login: %w", err)
	}

	rawVaultKey, err := vaultkey.Decrypt(input.MasterPassword, vaultKeyEnvelopeFromProto(response.GetVaultKey()))
	if err != nil {
		return Session{}, fmt.Errorf("%w: %w", ErrInvalidMasterPassword, err)
	}

	session, err := sessionFromAuthResponse(authResponse{
		AccessToken: response.GetAccessToken(),
		ExpiresAt:   response.GetAccessTokenExpiresAt(),
	}, rawVaultKey)
	if err != nil {
		return Session{}, err
	}

	if err = a.tokenStore.Save(ctx, TokenState{
		AccessToken: session.AccessToken,
		ExpiresAt:   session.AccessTokenExpiresAt,
	}); err != nil {
		return Session{}, fmt.Errorf("could not save token state: %w", err)
	}

	return session, nil
}

func (i *RegisterInput) validate() error {
	if strings.TrimSpace(i.Login) == "" {
		return fmt.Errorf("login is required")
	}

	if i.LoginPassword == "" {
		return fmt.Errorf("login password is required")
	}

	if i.MasterPassword == "" {
		return fmt.Errorf("master password is required")
	}

	return nil
}

func (i *LoginInput) validate() error {
	if strings.TrimSpace(i.Login) == "" {
		return fmt.Errorf("login is required")
	}

	if i.LoginPassword == "" {
		return fmt.Errorf("login password is required")
	}

	if i.MasterPassword == "" {
		return fmt.Errorf("master password is required")
	}

	return nil
}

func sessionFromAuthResponse(response authResponse, rawVaultKey []byte) (Session, error) {
	if strings.TrimSpace(response.AccessToken) == "" {
		return Session{}, fmt.Errorf("access token is required")
	}

	if response.ExpiresAt == nil {
		return Session{}, fmt.Errorf("access token expires at is required")
	}

	return Session{
		AccessToken:          response.AccessToken,
		AccessTokenExpiresAt: response.ExpiresAt.AsTime(),
		VaultKey:             rawVaultKey,
	}, nil
}

func vaultKeyEnvelopeToProto(envelope vaultkey.Envelope) *gophkeeperv1.VaultKeyEnvelope {
	return gophkeeperv1.VaultKeyEnvelope_builder{
		EncryptedVaultKey: envelope.EncryptedVaultKey,
		Nonce:             envelope.Nonce,
		EncryptionAlg:     envelope.EncryptionAlg,
		KdfParams: gophkeeperv1.KDFParams_builder{
			Algorithm:   envelope.KDFParams.Algorithm,
			Salt:        envelope.KDFParams.Salt,
			TimeCost:    envelope.KDFParams.TimeCost,
			MemoryKib:   envelope.KDFParams.MemoryKiB,
			Parallelism: uint32(envelope.KDFParams.Parallelism),
			KeyLength:   envelope.KDFParams.KeyLength,
		}.Build(),
	}.Build()
}

func vaultKeyEnvelopeFromProto(envelope *gophkeeperv1.VaultKeyEnvelope) vaultkey.Envelope {
	if envelope == nil {
		return vaultkey.Envelope{}
	}

	kdfParams := envelope.GetKdfParams()

	return vaultkey.Envelope{
		EncryptedVaultKey: envelope.GetEncryptedVaultKey(),
		Nonce:             envelope.GetNonce(),
		EncryptionAlg:     envelope.GetEncryptionAlg(),
		KDFParams: vaultkey.KDFParams{
			Algorithm:   kdfParams.GetAlgorithm(),
			Salt:        kdfParams.GetSalt(),
			TimeCost:    kdfParams.GetTimeCost(),
			MemoryKiB:   kdfParams.GetMemoryKib(),
			Parallelism: uint8(kdfParams.GetParallelism()),
			KeyLength:   kdfParams.GetKeyLength(),
		},
	}
}
