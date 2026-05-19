package vault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresRepositoryCreateItem(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	userID := createTestUser(t, ctx, db)
	itemID, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID() error = %v", err)
	}

	defer func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
	}()

	repository := NewPostgresRepository(db)
	params := CreateItemParams{
		ItemID: itemID,
		UserID: userID,
		Type:   ItemTypeLoginPassword,
		Metadata: EncryptedData{
			Ciphertext: []byte("encrypted-metadata"),
			Nonce:      []byte("metadata-nonce"),
		},
		Payload: EncryptedData{
			Ciphertext: []byte("encrypted-payload"),
			Nonce:      []byte("payload-nonce"),
		},
		EncryptionAlg:        "aes-256-gcm",
		PayloadSchemaVersion: 1,
	}

	item, err := repository.CreateItem(ctx, params)
	if err != nil {
		t.Fatalf("CreateItem() error = %v", err)
	}

	if item.ID != itemID {
		t.Fatalf("ID = %q, want %q", item.ID, itemID)
	}

	if item.UserID != userID {
		t.Fatalf("UserID = %q, want %q", item.UserID, userID)
	}

	if item.Type != ItemTypeLoginPassword {
		t.Fatalf("Type = %q, want %q", item.Type, ItemTypeLoginPassword)
	}

	if !bytes.Equal(item.Metadata.Ciphertext, params.Metadata.Ciphertext) {
		t.Fatalf("Metadata ciphertext does not match input")
	}

	if !bytes.Equal(item.Metadata.Nonce, params.Metadata.Nonce) {
		t.Fatalf("Metadata nonce does not match input")
	}

	if !bytes.Equal(item.Payload.Ciphertext, params.Payload.Ciphertext) {
		t.Fatalf("Payload ciphertext does not match input")
	}

	if !bytes.Equal(item.Payload.Nonce, params.Payload.Nonce) {
		t.Fatalf("Payload nonce does not match input")
	}

	if item.EncryptionAlg != params.EncryptionAlg {
		t.Fatalf("EncryptionAlg = %q, want %q", item.EncryptionAlg, params.EncryptionAlg)
	}

	if item.PayloadSchemaVersion != params.PayloadSchemaVersion {
		t.Fatalf("PayloadSchemaVersion = %d, want %d", item.PayloadSchemaVersion, params.PayloadSchemaVersion)
	}

	if item.Version != 1 {
		t.Fatalf("Version = %d, want 1", item.Version)
	}

	if item.CreatedAt.IsZero() {
		t.Fatalf("CreatedAt is zero")
	}

	if item.UpdatedAt.IsZero() {
		t.Fatalf("UpdatedAt is zero")
	}

	if item.DeletedAt != nil {
		t.Fatalf("DeletedAt = %v, want nil", item.DeletedAt)
	}
}

func TestPostgresRepositoryFindItemByID(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	userID := createTestUser(t, ctx, db)
	itemID, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID() error = %v", err)
	}

	defer func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
	}()

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO vault_items (
			id,
			user_id,
			type,
			encrypted_metadata,
			metadata_nonce,
			encrypted_payload,
			payload_nonce,
			encryption_alg,
			payload_schema_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		itemID,
		userID,
		string(ItemTypeText),
		[]byte("encrypted-metadata"),
		[]byte("metadata-nonce"),
		[]byte("encrypted-payload"),
		[]byte("payload-nonce"),
		"aes-256-gcm",
		2,
	)
	if err != nil {
		t.Fatalf("insert vault item error = %v", err)
	}

	repository := NewPostgresRepository(db)

	item, err := repository.FindItemByID(ctx, itemID)
	if err != nil {
		t.Fatalf("FindItemByID() error = %v", err)
	}

	if item.ID != itemID {
		t.Fatalf("ID = %q, want %q", item.ID, itemID)
	}

	if item.UserID != userID {
		t.Fatalf("UserID = %q, want %q", item.UserID, userID)
	}

	if item.Type != ItemTypeText {
		t.Fatalf("Type = %q, want %q", item.Type, ItemTypeText)
	}

	if !bytes.Equal(item.Metadata.Ciphertext, []byte("encrypted-metadata")) {
		t.Fatalf("Metadata ciphertext does not match stored value")
	}

	if !bytes.Equal(item.Metadata.Nonce, []byte("metadata-nonce")) {
		t.Fatalf("Metadata nonce does not match stored value")
	}

	if !bytes.Equal(item.Payload.Ciphertext, []byte("encrypted-payload")) {
		t.Fatalf("Payload ciphertext does not match stored value")
	}

	if !bytes.Equal(item.Payload.Nonce, []byte("payload-nonce")) {
		t.Fatalf("Payload nonce does not match stored value")
	}

	if item.EncryptionAlg != "aes-256-gcm" {
		t.Fatalf("EncryptionAlg = %q, want aes-256-gcm", item.EncryptionAlg)
	}

	if item.PayloadSchemaVersion != 2 {
		t.Fatalf("PayloadSchemaVersion = %d, want 2", item.PayloadSchemaVersion)
	}
}

func TestPostgresRepositoryFindItemByIDReturnsItemNotFound(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	repository := NewPostgresRepository(db)

	missingItemID, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID() error = %v", err)
	}

	_, err = repository.FindItemByID(ctx, missingItemID)
	if !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("FindItemByID() error = %v, want ErrItemNotFound", err)
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("GOPHKEEPER_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("GOPHKEEPER_TEST_DATABASE_DSN is not set")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("db.Close() error = %v", err)
		}
	})

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("db.PingContext() error = %v", err)
	}

	return db
}

func createTestUser(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()

	userID, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID() error = %v", err)
	}

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO users (id, login, password_hash)
		VALUES ($1, $2, $3)`,
		userID,
		"vault-repo-"+userID+"@example.com",
		"$argon2id$hash",
	)
	if err != nil {
		t.Fatalf("insert user error = %v", err)
	}

	return userID
}
