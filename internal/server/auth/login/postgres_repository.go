package login

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PostgresRepository ищет данные пользователя для login в PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository создает PostgreSQL repository для login
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{
		db: db,
	}
}

// FindUserByLogin возвращает пользователя, password hash и encrypted vault metadata
func (r *PostgresRepository) FindUserByLogin(ctx context.Context, login string) (User, error) {
	var u User

	err := r.db.QueryRowContext(
		ctx,
		`SELECT
			u.id,
			u.login,
			u.password_hash,
			uv.encrypted_vault_key,
			uv.vault_key_nonce,
			uv.vault_key_encryption_alg,
			uv.kdf_alg,
			uv.kdf_salt,
			uv.kdf_time_cost,
			uv.kdf_memory_kib,
			uv.kdf_parallelism,
			uv.kdf_key_length
		FROM users u
		JOIN user_vaults uv ON uv.user_id = u.id
		WHERE u.login = $1`,
		login,
	).Scan(
		&u.ID,
		&u.Login,
		&u.PasswordHash,
		&u.VaultKey.EncryptedVaultKey,
		&u.VaultKey.Nonce,
		&u.VaultKey.EncryptionAlg,
		&u.VaultKey.KDFParams.Algorithm,
		&u.VaultKey.KDFParams.Salt,
		&u.VaultKey.KDFParams.TimeCost,
		&u.VaultKey.KDFParams.MemoryKiB,
		&u.VaultKey.KDFParams.Parallelism,
		&u.VaultKey.KDFParams.KeyLength,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUserNotFound
		}

		return User{}, fmt.Errorf("find user by login: %w", err)
	}

	return u, nil
}
