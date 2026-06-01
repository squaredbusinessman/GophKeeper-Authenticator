// Package app собирает и запускает серверное приложение
package app

import (
	"context"
	"errors"
	"fmt"

	serverblob "github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/blob"
	miniostore "github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/blob/minio"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/database"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/migrations"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/logger"
)

// Run запускает серверное приложение
func Run(parent context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load server config: %w", err)
	}

	log, err := logger.New(cfg.LogMode)
	if err != nil {
		return fmt.Errorf("create configured logger: %w", err)
	}
	defer func() {
		_ = log.Sync()
	}()

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

	var blobStore serverblob.ObjectStore
	if cfg.BlobStorageEnabled {
		blobStore, err = miniostore.NewStore(miniostore.Config{
			Endpoint:  cfg.MinIOEndpoint,
			AccessKey: cfg.MinIOAccessKey,
			SecretKey: cfg.MinIOSecretKey,
			Bucket:    cfg.MinIOBucket,
			UseSSL:    cfg.MinIOUseSSL,
		})
		if err != nil {
			log.Error("failed to create blob storage", zap.Error(err))
			return fmt.Errorf("create blob storage: %w", err)
		}

		if err = blobStore.EnsureBucket(parent); err != nil {
			log.Error("failed to prepare blob storage", zap.Error(err))
			return fmt.Errorf("prepare blob storage: %w", err)
		}

		log.Info("blob storage ready", zap.String("bucket", cfg.MinIOBucket))
	}

	server, err := grpcserver.New(cfg, log, db, blobStore)
	if err != nil {
		log.Error("failed to create grpc server", zap.Error(err))
		return fmt.Errorf("create grpc server: %w", err)
	}

	errCh := make(chan error, 1)

	go func() {
		errCh <- server.Start()
	}()

	select {
	case <-parent.Done():
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
