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

// ListItems возвращает encrypted vault items пользователя
func (r *PostgresRepository) ListItems(ctx context.Context, params ListItemsParams) ([]Item, error) {
	query := `SELECT
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
		WHERE user_id = $1`

	if !params.IncludeDeleted {
		query += ` AND deleted_at IS NULL`
	}

	query += ` ORDER BY updated_at DESC, id DESC`

	rows, err := r.db.QueryContext(ctx, query, params.UserID)
	if err != nil {
		return nil, fmt.Errorf("list vault items: %w", err)
	}
	defer rows.Close()

	var items []Item
	for rows.Next() {
		var item Item
		if err = rows.Scan(
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
		); err != nil {
			return nil, fmt.Errorf("scan vault item: %w", err)
		}

		items = append(items, item)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vault items: %w", err)
	}

	return items, nil
}

// UpdateItem обновляет encrypted vault item при совпадении owner и expected version
func (r *PostgresRepository) UpdateItem(ctx context.Context, params UpdateItemParams) (Item, error) {
	var item Item

	err := r.db.QueryRowContext(
		ctx,
		`UPDATE vault_items
		SET
			type = $4,
			encrypted_metadata = $5,
			metadata_nonce = $6,
			encrypted_payload = $7,
			payload_nonce = $8,
			encryption_alg = $9,
			payload_schema_version = $10,
			version = version + 1,
			updated_at = NOW()
		WHERE id = $1
			AND user_id = $2
			AND version = $3
			AND deleted_at IS NULL
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
		params.ExpectedVersion,
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
		if errors.Is(err, sql.ErrNoRows) {
			return Item{}, ErrVersionConflict
		}

		return Item{}, fmt.Errorf("update vault item: %w", err)
	}

	return item, nil
}

// DeleteItem мягко удаляет vault item при совпадении owner и expected version
func (r *PostgresRepository) DeleteItem(ctx context.Context, params DeleteItemParams) (DeleteItemResult, error) {
	var result DeleteItemResult

	err := r.db.QueryRowContext(
		ctx,
		`UPDATE vault_items
		SET
			version = version + 1,
			updated_at = NOW(),
			deleted_at = NOW()
		WHERE id = $1
			AND user_id = $2
			AND version = $3
			AND deleted_at IS NULL
		RETURNING
			id,
			version,
			deleted_at`,
		params.ItemID,
		params.UserID,
		params.ExpectedVersion,
	).Scan(
		&result.ItemID,
		&result.Version,
		&result.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeleteItemResult{}, ErrVersionConflict
		}

		return DeleteItemResult{}, fmt.Errorf("delete vault item: %w", err)
	}

	return result, nil
}

// SyncItems возвращает changed items пользователя, включая tombstones
func (r *PostgresRepository) SyncItems(ctx context.Context, params SyncItemsParams) (SyncItemsResult, error) {
	rows, err := r.db.QueryContext(
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
		WHERE user_id = $1
			AND updated_at > $2
		ORDER BY updated_at ASC, id ASC`,
		params.UserID,
		params.ChangedAfter,
	)
	if err != nil {
		return SyncItemsResult{}, fmt.Errorf("sync vault items: %w", err)
	}
	defer rows.Close()

	result := SyncItemsResult{
		NextChangedAfter: params.ChangedAfter,
	}

	for rows.Next() {
		var item Item
		if err = rows.Scan(
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
		); err != nil {
			return SyncItemsResult{}, fmt.Errorf("scan synced vault item: %w", err)
		}

		result.Items = append(result.Items, item)
		if item.UpdatedAt.After(result.NextChangedAfter) {
			result.NextChangedAfter = item.UpdatedAt
		}
	}

	if err = rows.Err(); err != nil {
		return SyncItemsResult{}, fmt.Errorf("iterate synced vault items: %w", err)
	}

	return result, nil
}
