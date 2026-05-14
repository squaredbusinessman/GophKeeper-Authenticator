// Package migrations запускает PostgreSQL-миграции приложения
package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

// Up применяет все новые миграции goose
func Up(ctx context.Context, db *sql.DB, dir string) error {
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}

	if err := goose.UpContext(ctx, db, dir); err != nil {
		return fmt.Errorf("apply goose migrations: %w", err)
	}

	return nil
}
