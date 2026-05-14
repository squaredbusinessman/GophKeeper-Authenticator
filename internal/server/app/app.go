// Package app собирает и запускает серверное приложение
package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/database"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/migrations"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/logger"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/shutdown"
)

// Run запускает серверное приложение
func Run(parent context.Context) error {
	log, err := logger.New()
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer func() {
		_ = log.Sync()
	}()

	cfg, err := config.Load()
	if err != nil {
		log.Error("failed to load server config", zap.Error(err))
		return fmt.Errorf("load server config: %w", err)
	}

	db, err := database.Open(parent, cfg)
	if err != nil {
		log.Error("failed to open database", zap.Error(err))
		return fmt.Errorf("connect database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error("failed to close database", zap.Error(err))
		}
	}()

	log.Info("database connection established")

	if cfg.MigrationsEnabled {
		log.Info("database migrations started", zap.String("dir", cfg.MigrationsDir))

		if err = migrations.Up(parent, db, cfg.MigrationsDir); err != nil {
			log.Error("failed to apply database migrations", zap.Error(err))
			return fmt.Errorf("apply database migrations: %w", err)
		}

		log.Info("database migrations applied", zap.String("dir", cfg.MigrationsDir))
	}

	server, err := grpcserver.New(cfg, log)
	if err != nil {
		log.Error("failed to create grpc server", zap.Error(err))
		return fmt.Errorf("create grpc server: %w", err)
	}

	ctx, stop := shutdown.Context(parent)
	defer stop()

	errCh := make(chan error, 1)

	go func() {
		errCh <- server.Start()
	}()

	select {
	case <-ctx.Done():
		server.Stop()
		return nil

	case err := <-errCh:
		if err == nil || errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}

		log.Error("grpc server stopped with error", zap.Error(err))
		return fmt.Errorf("serve grpc: %w", err)
	}
}
