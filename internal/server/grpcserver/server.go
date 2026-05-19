// Package grpcserver собирает gRPC-сервер приложения
package grpcserver

import (
	"database/sql"
	"net"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/login"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/register"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/token"
	"go.uber.org/zap"
	"google.golang.org/grpc"

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
func New(cfg *config.Config, logger *zap.Logger, db *sql.DB) (*Server, error) {
	listener, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		return nil, err
	}

	tokenIssuer := token.NewIssuer(cfg.AccessTokenSecret, cfg.AccessTokenTTL)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(AuthUnaryInterceptor(tokenIssuer)),
	)

	registerRepository := register.NewPostgresRepository(db)
	registerUseCase := register.NewService(registerRepository, nil, nil)

	loginRepository := login.NewPostgresRepository(db)
	loginUseCase := login.NewService(loginRepository, nil, tokenIssuer)

	gophkeeperv1.RegisterAuthServiceServer(grpcServer, handler.NewAuthHandler(registerUseCase, loginUseCase))
	gophkeeperv1.RegisterVaultServiceServer(grpcServer, handler.NewVaultHandler())

	return &Server{
		grpcServer: grpcServer,
		listener:   listener,
		logger:     logger,
		address:    cfg.GRPCAddress,
		tlsEnabled: cfg.GRPCTLSEnabled,
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
