package login

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/register"
)

func TestPostgresRepositoryFindUserByLogin(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("GOPHKEEPER_TEST_DATABASE_DSN is not set")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("db.Close() error = %v", err)
		}
	}()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("db.PingContext() error = %v", err)
	}

	userID, err := register.NewUUID()
	if err != nil {
		t.Fatalf("register.NewUUID() error = %v", err)
	}

	login := "login-repo-" + userID + "@example.com"
	passwordHash := "$argon2id$hash"
	vaultKey := validVaultKey()

	defer func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
	}()

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO users (id, login, password_hash)
		VALUES ($1, $2, $3)`,
		userID,
		login,
		passwordHash,
	)
	if err != nil {
		t.Fatalf("insert user error = %v", err)
	}

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO user_vaults (
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
		userID,
		vaultKey.EncryptedVaultKey,
		vaultKey.Nonce,
		vaultKey.EncryptionAlg,
		vaultKey.KDFParams.Algorithm,
		vaultKey.KDFParams.Salt,
		int64(vaultKey.KDFParams.TimeCost),
		int64(vaultKey.KDFParams.MemoryKiB),
		int64(vaultKey.KDFParams.Parallelism),
		int64(vaultKey.KDFParams.KeyLength),
	)
	if err != nil {
		t.Fatalf("insert user vault error = %v", err)
	}

	repository := NewPostgresRepository(db)

	user, err := repository.FindUserByLogin(ctx, login)
	if err != nil {
		t.Fatalf("FindUserByLogin() error = %v", err)
	}

	if user.ID != userID {
		t.Fatalf("ID = %q, want %q", user.ID, userID)
	}

	if user.Login != login {
		t.Fatalf("Login = %q, want %q", user.Login, login)
	}

	if user.PasswordHash != passwordHash {
		t.Fatalf("PasswordHash = %q, want %q", user.PasswordHash, passwordHash)
	}

	if !bytes.Equal(user.VaultKey.EncryptedVaultKey, vaultKey.EncryptedVaultKey) {
		t.Fatalf("EncryptedVaultKey does not match stored value")
	}

	if !bytes.Equal(user.VaultKey.Nonce, vaultKey.Nonce) {
		t.Fatalf("Nonce does not match stored value")
	}

	if user.VaultKey.EncryptionAlg != vaultKey.EncryptionAlg {
		t.Fatalf("EncryptionAlg = %q, want %q", user.VaultKey.EncryptionAlg, vaultKey.EncryptionAlg)
	}

	if !bytes.Equal(user.VaultKey.KDFParams.Salt, vaultKey.KDFParams.Salt) {
		t.Fatalf("KDF salt does not match stored value")
	}

	if user.VaultKey.KDFParams.MemoryKiB != vaultKey.KDFParams.MemoryKiB {
		t.Fatalf("KDF memory = %d, want %d", user.VaultKey.KDFParams.MemoryKiB, vaultKey.KDFParams.MemoryKiB)
	}
}

func TestPostgresRepositoryFindUserByLoginReturnsUserNotFound(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("GOPHKEEPER_TEST_DATABASE_DSN is not set")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("db.Close() error = %v", err)
		}
	}()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("db.PingContext() error = %v", err)
	}

	repository := NewPostgresRepository(db)

	_, err = repository.FindUserByLogin(ctx, "missing-user@example.com")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("FindUserByLogin() error = %v, want ErrUserNotFound", err)
	}
}
