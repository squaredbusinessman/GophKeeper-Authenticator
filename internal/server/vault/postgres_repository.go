package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PostgresRepository сохраняет и загружает encrypted vault items в PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository создает PostgreSQL repository для vault items
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{
		db: db,
	}
}

// CreateItem создает encrypted vault item и возвращает его с серверными полями
func (r *PostgresRepository) CreateItem(ctx context.Context, params CreateItemParams) (Item, error) {
	var item Item

	err := r.db.QueryRowContext(
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
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING
			id,
			user_id,
			type,
			encrypted_metadata,
			metadata_nonce,
			encrypted_payload,
			payload_nonce,
			encryption_alg,
			payload_schema_version,
			version,
			created_at,
			updated_at,
			deleted_at`,
		params.ItemID,
		params.UserID,
		string(params.Type),
		params.Metadata.Ciphertext,
		params.Metadata.Nonce,
		params.Payload.Ciphertext,
		params.Payload.Nonce,
		params.EncryptionAlg,
		params.PayloadSchemaVersion,
	).Scan(
		&item.ID,
		&item.UserID,
		&item.Type,
		&item.Metadata.Ciphertext,
		&item.Metadata.Nonce,
		&item.Payload.Ciphertext,
		&item.Payload.Nonce,
		&item.EncryptionAlg,
		&item.PayloadSchemaVersion,
		&item.Version,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.DeletedAt,
	)
	if err != nil {
		return Item{}, fmt.Errorf("create vault item: %w", err)
	}

	return item, nil
}

// FindItemByID возвращает encrypted vault item по id
func (r *PostgresRepository) FindItemByID(ctx context.Context, itemID string) (Item, error) {
	var item Item

	err := r.db.QueryRowContext(
		ctx,
		`SELECT
			id,
			user_id,
			type,
			encrypted_metadata,
			metadata_nonce,
			encrypted_payload,
			payload_nonce,
			encryption_alg,
			payload_schema_version,
			version,
			created_at,
			updated_at,
			deleted_at
		FROM vault_items
		WHERE id = $1`,
		itemID,
	).Scan(
		&item.ID,
		&item.UserID,
		&item.Type,
		&item.Metadata.Ciphertext,
		&item.Metadata.Nonce,
		&item.Payload.Ciphertext,
		&item.Payload.Nonce,
		&item.EncryptionAlg,
		&item.PayloadSchemaVersion,
		&item.Version,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Item{}, ErrItemNotFound
		}

		return Item{}, fmt.Errorf("find vault item by id: %w", err)
	}

	return item, nil
}
