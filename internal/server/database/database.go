// Package database создает подключение к PostgreSQL
package database

import (
	"context"
	"database/sql"
	"fmt"

	// Регистрирует pgx driver для database/sql
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/config"
)

// Open создает подключение к PostgreSQL и проверяет доступность БД
func Open(ctx context.Context, cfg *config.Config) (*sql.DB, error) {
	db, err := sql.Open("pgx", cfg.DatabaseDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(ctx, cfg.DatabasePingTTL)
	defer pingCancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	return db, nil
}
