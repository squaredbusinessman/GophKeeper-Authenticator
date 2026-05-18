package register

import (
	"context"
	"database/sql"
	"fmt"
)

// PostgresRepository сохраняет данные регистрации в PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository создает PostgreSQL repository регистрации
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{
		db: db,
	}
}

// CreateUserWithVault атомарно создает пользователя и его encrypted vault key
func (r *PostgresRepository) CreateUserWithVault(ctx context.Context, params CreateUserWithVaultParams) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin register transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback()
	}()

	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO users (id, login, password_hash) VALUES ($1, $2, $3) ON CONFLICT (login) DO NOTHING`,
		params.UserID,
		params.Login,
		params.PasswordHash,
	)
	if err != nil {
		return fmt.Errorf("insert user in db: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check inserted user rows: %w", err)
	}

	if rowsAffected == 0 {
		return ErrLoginAlreadyExists
	}

	_, err = tx.ExecContext(
		ctx, `INSERT INTO user_vaults (
                         user_id,
                         encrypted_vault_key,
                         vault_key_nonce,
                         vault_key_encryption_alg,
                         kdf_alg,
                         kdf_salt,
                         kdf_time_cost,
                         kdf_memory_kib,
                         kdf_parallelism,
                         kdf_key_length
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		params.UserID,
		params.VaultKey.EncryptedVaultKey,
		params.VaultKey.Nonce,
		params.VaultKey.EncryptionAlg,
		params.VaultKey.KDFParams.Algorithm,
		params.VaultKey.KDFParams.Salt,
		int64(params.VaultKey.KDFParams.TimeCost),
		int64(params.VaultKey.KDFParams.MemoryKiB),
		int64(params.VaultKey.KDFParams.Parallelism),
		int64(params.VaultKey.KDFParams.KeyLength),
	)
	if err != nil {
		return fmt.Errorf("insert user vault in db: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit register transaction: %w", err)
	}

	return nil
}
