package register

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresRepositoryCreateUserWithVault(t *testing.T) {
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
	userID, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID() error = %v", err)
	}

	params := CreateUserWithVaultParams{
		UserID:       userID,
		Login:        "repo-test-" + userID + "@example.com",
		PasswordHash: "$argon2id$hash",
		VaultKey:     validInput().VaultKey,
	}

	defer func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
	}()

	if err := repository.CreateUserWithVault(ctx, params); err != nil {
		t.Fatalf("CreateUserWithVault() error = %v", err)
	}

	var storedLogin string
	var storedPasswordHash string
	var encryptedVaultKey []byte
	var vaultKeyNonce []byte
	var kdfAlg string
	var kdfMemoryKiB int

	err = db.QueryRowContext(
		ctx,
		`SELECT u.login, u.password_hash, uv.encrypted_vault_key, uv.vault_key_nonce, uv.kdf_alg, uv.kdf_memory_kib
		FROM users u
		JOIN user_vaults uv ON uv.user_id = u.id
		WHERE u.id = $1`,
		userID,
	).Scan(
		&storedLogin,
		&storedPasswordHash,
		&encryptedVaultKey,
		&vaultKeyNonce,
		&kdfAlg,
		&kdfMemoryKiB,
	)
	if err != nil {
		t.Fatalf("QueryRowContext() error = %v", err)
	}

	if storedLogin != params.Login {
		t.Fatalf("stored login = %q, want %q", storedLogin, params.Login)
	}

	if storedPasswordHash != params.PasswordHash {
		t.Fatalf("stored password hash = %q, want %q", storedPasswordHash, params.PasswordHash)
	}

	if !bytes.Equal(encryptedVaultKey, params.VaultKey.EncryptedVaultKey) {
		t.Fatalf("stored encrypted vault key does not match original value")
	}

	if !bytes.Equal(vaultKeyNonce, params.VaultKey.Nonce) {
		t.Fatalf("stored vault key nonce does not match original value")
	}

	if kdfAlg != params.VaultKey.KDFParams.Algorithm {
		t.Fatalf("stored kdf algorithm = %q, want %q", kdfAlg, params.VaultKey.KDFParams.Algorithm)
	}

	if kdfMemoryKiB != int(params.VaultKey.KDFParams.MemoryKiB) {
		t.Fatalf("stored kdf memory = %d, want %d", kdfMemoryKiB, params.VaultKey.KDFParams.MemoryKiB)
	}
}

func TestPostgresRepositoryReturnsErrorForDuplicateLogin(t *testing.T) {
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
	firstUserID, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID() first error = %v", err)
	}

	secondUserID, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID() second error = %v", err)
	}

	login := "repo-duplicate-" + firstUserID + "@example.com"

	defer func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1, $2)`, firstUserID, secondUserID)
	}()

	firstParams := CreateUserWithVaultParams{
		UserID:       firstUserID,
		Login:        login,
		PasswordHash: "$argon2id$hash",
		VaultKey:     validInput().VaultKey,
	}

	secondParams := firstParams
	secondParams.UserID = secondUserID

	if err := repository.CreateUserWithVault(ctx, firstParams); err != nil {
		t.Fatalf("CreateUserWithVault() first error = %v", err)
	}

	err = repository.CreateUserWithVault(ctx, secondParams)
	if !errors.Is(err, ErrLoginAlreadyExists) {
		t.Fatalf("CreateUserWithVault() error = %v, want ErrLoginAlreadyExists", err)
	}
}
