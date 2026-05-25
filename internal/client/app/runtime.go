// Package app собирает клиентские зависимости для CLI и TUI
package app

import (
	"fmt"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Runtime содержит общие клиентские зависимости приложения
type Runtime struct {
	Config       *config.Config
	Conn         *grpc.ClientConn
	AuthClient   gophkeeperv1.AuthServiceClient
	VaultClient  gophkeeperv1.VaultServiceClient
	TokenStore   *core.FileTokenStore
	AuthService  *core.AuthService
	VaultService *core.VaultService
}

// LoadRuntime загружает config и создает клиентские зависимости
func LoadRuntime() (*Runtime, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}

	return NewRuntime(cfg)
}

// NewRuntime создает клиентские зависимости из готового config
func NewRuntime(cfg *config.Config) (*Runtime, error) {
	if cfg == nil {
		return nil, fmt.Errorf("client config is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate client config: %w", err)
	}

	transportCredentials, err := transportCredentialsFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(
		cfg.ServerAddress,
		grpc.WithTransportCredentials(transportCredentials),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating grpc client: %w", err)
	}

	authClient := gophkeeperv1.NewAuthServiceClient(conn)
	vaultClient := gophkeeperv1.NewVaultServiceClient(conn)
	tokenStore := core.NewFileTokenStore(cfg.TokenFile)

	return &Runtime{
		Config:       cfg,
		Conn:         conn,
		AuthClient:   authClient,
		VaultClient:  vaultClient,
		TokenStore:   tokenStore,
		AuthService:  core.NewAuthService(authClient, tokenStore),
		VaultService: core.NewVaultService(vaultClient),
	}, nil
}

// Close закрывает gRPC-соединение клиента
func (r *Runtime) Close() error {
	if r == nil || r.Conn == nil {
		return nil
	}

	return r.Conn.Close()
}

func transportCredentialsFromConfig(cfg *config.Config) (credentials.TransportCredentials, error) {
	if !cfg.ServerTLSEnabled {
		return insecure.NewCredentials(), nil
	}

	tlsCredentials, err := credentials.NewClientTLSFromFile(cfg.ServerTLSCertFile, "")
	if err != nil {
		return nil, fmt.Errorf("load server TLS credentials: %w", err)
	}

	return tlsCredentials, nil
}
