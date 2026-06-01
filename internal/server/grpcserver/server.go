// Package grpcserver собирает gRPC-сервер приложения
package grpcserver

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/login"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/register"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/token"
	serverblob "github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/blob"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/vault"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver/handler"
)

// Server содержит gRPC-сервер и сетевой listener
type Server struct {
	grpcServer *grpc.Server
	listener   net.Listener
	logger     *zap.Logger
	address    string
	tlsEnabled bool
}

// New создает и настраивает gRPC-сервер
func New(cfg *config.Config, logger *zap.Logger, db *sql.DB, blobStore serverblob.ObjectStore) (*Server, error) {
	tokenIssuer := token.NewIssuer(cfg.AccessTokenSecret, cfg.AccessTokenTTL)
	serverOptions := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			AuthUnaryInterceptor(tokenIssuer),
			LoggingUnaryInterceptor(logger),
		),
		grpc.ChainStreamInterceptor(
			AuthStreamInterceptor(tokenIssuer),
		),
	}

	creds, err := credentials.NewServerTLSFromFile(cfg.GRPCTLSCertFile, cfg.GRPCTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load grpc TLS credentials: %w", err)
	}
	serverOptions = append(serverOptions, grpc.Creds(creds))

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", cfg.GRPCAddress)
	if err != nil {
		return nil, err
	}
	listenerOwned := true
	defer func() {
		if listenerOwned {
			_ = listener.Close()
		}
	}()

	grpcServer := grpc.NewServer(serverOptions...)

	registerRepository := register.NewPostgresRepository(db)
	registerUseCase := register.NewService(registerRepository, nil, nil, tokenIssuer)

	loginRepository := login.NewPostgresRepository(db)
	loginUseCase := login.NewService(loginRepository, nil, tokenIssuer)

	vaultRepository := vault.NewPostgresRepository(db)
	vaultUseCase := vault.NewService(vaultRepository, nil)

	gophkeeperv1.RegisterAuthServiceServer(grpcServer, handler.NewAuthHandler(registerUseCase, loginUseCase))
	gophkeeperv1.RegisterVaultServiceServer(grpcServer, handler.NewVaultHandler(vaultUseCase))

	if cfg.BlobStorageEnabled {
		if blobStore == nil {
			return nil, fmt.Errorf("blob storage is enabled but object store is not configured")
		}

		blobRepository := serverblob.NewPostgresRepository(db)
		blobUseCase := serverblob.NewService(blobRepository, blobStore, serverblob.IDGeneratorFunc(serverblob.NewUUID), serverblob.Config{
			Bucket:    cfg.MinIOBucket,
			ChunkSize: cfg.BlobChunkSize,
			MaxSize:   cfg.BlobMaxSize,
			UploadTTL: cfg.BlobUploadTTL,
		})

		gophkeeperv1.RegisterBlobServiceServer(grpcServer, handler.NewBlobHandler(blobUseCase))
	}

	listenerOwned = false
	return &Server{
		grpcServer: grpcServer,
		listener:   listener,
		logger:     logger,
		address:    cfg.GRPCAddress,
		tlsEnabled: true,
	}, nil
}

// Start запускает обработку gRPC-запросов
func (s *Server) Start() error {
	s.logger.Info(
		"grpc server started",
		zap.String("address", s.address),
		zap.Bool("tls_enabled", s.tlsEnabled),
	)
	return s.grpcServer.Serve(s.listener)
}

// Stop корректно останавливает gRPC-сервер
func (s *Server) Stop() {
	s.logger.Info("grpc server shutdown started")
	s.grpcServer.GracefulStop()
	s.logger.Info("grpc server stopped")
}
