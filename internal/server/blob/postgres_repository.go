package blob

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PostgresRepository сохраняет metadata encrypted blob storage в PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository создает PostgreSQL repository для blob metadata
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{
		db: db,
	}
}

// CreateUpload создает upload session
func (r *PostgresRepository) CreateUpload(ctx context.Context, params CreateUploadParams) (Upload, error) {
	var upload Upload

	err := r.db.QueryRowContext(
		ctx,
		`INSERT INTO blob_uploads (
			id,
			user_id,
			status,
			chunk_size,
			expected_size,
			expected_chunks,
			checksum_sha256,
			expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING
			id,
			user_id,
			status,
			chunk_size,
			expected_size,
			expected_chunks,
			received_chunks,
			checksum_sha256,
			expires_at`,
		params.UploadID,
		params.UserID,
		params.Status,
		params.ChunkSize,
		params.ExpectedSize,
		params.ExpectedChunks,
		params.ChecksumSHA256,
		params.ExpiresAt,
	).Scan(
		&upload.ID,
		&upload.UserID,
		&upload.Status,
		&upload.ChunkSize,
		&upload.ExpectedSize,
		&upload.ExpectedChunks,
		&upload.ReceivedChunks,
		&upload.ChecksumSHA256,
		&upload.ExpiresAt,
	)
	if err != nil {
		return Upload{}, fmt.Errorf("create blob upload: %w", err)
	}

	return upload, nil
}

// FindUploadByID возвращает upload session по id
func (r *PostgresRepository) FindUploadByID(ctx context.Context, uploadID string) (Upload, error) {
	var upload Upload

	err := r.db.QueryRowContext(
		ctx,
		`SELECT
			id,
			user_id,
			status,
			chunk_size,
			expected_size,
			expected_chunks,
			received_chunks,
			checksum_sha256,
			expires_at
		FROM blob_uploads
		WHERE id = $1`,
		uploadID,
	).Scan(
		&upload.ID,
		&upload.UserID,
		&upload.Status,
		&upload.ChunkSize,
		&upload.ExpectedSize,
		&upload.ExpectedChunks,
		&upload.ReceivedChunks,
		&upload.ChecksumSHA256,
		&upload.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Upload{}, ErrUploadNotFound
		}

		return Upload{}, fmt.Errorf("find blob upload: %w", err)
	}

	return upload, nil
}

// AddUploadPart сохраняет metadata принятого chunk
func (r *PostgresRepository) AddUploadPart(ctx context.Context, params AddUploadPartParams) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin add blob upload part tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO blob_upload_parts (
			upload_id,
			chunk_index,
			object_key,
			size_bytes,
			checksum_sha256
		) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (upload_id, chunk_index) DO UPDATE SET
			object_key = EXCLUDED.object_key,
			size_bytes = EXCLUDED.size_bytes,
			checksum_sha256 = EXCLUDED.checksum_sha256,
			created_at = NOW()`,
		params.UploadID,
		params.ChunkIndex,
		params.ObjectKey,
		params.SizeBytes,
		params.ChecksumSHA256,
	); err != nil {
		return fmt.Errorf("upsert blob upload part: %w", err)
	}

	result, err := tx.ExecContext(
		ctx,
		`UPDATE blob_uploads
		SET
			status = CASE WHEN status = $2 THEN $3 ELSE status END,
			received_chunks = (
				SELECT COUNT(*)
				FROM blob_upload_parts
				WHERE upload_id = $1
			),
			updated_at = NOW()
		WHERE id = $1
			AND status IN ($2, $3)`,
		params.UploadID,
		UploadStatusCreated,
		UploadStatusUploading,
	)
	if err != nil {
		return fmt.Errorf("update blob upload after part: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check blob upload update result: %w", err)
	}
	if rowsAffected == 0 {
		return ErrUploadNotFound
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit add blob upload part tx: %w", err)
	}

	return nil
}

// ListUploadParts возвращает chunks upload session в порядке chunk index
func (r *PostgresRepository) ListUploadParts(ctx context.Context, uploadID string) ([]UploadPart, error) {
	rows, err := r.db.QueryContext(
		ctx,
		`SELECT
			upload_id,
			chunk_index,
			object_key,
			size_bytes,
			checksum_sha256
		FROM blob_upload_parts
		WHERE upload_id = $1
		ORDER BY chunk_index ASC`,
		uploadID,
	)
	if err != nil {
		return nil, fmt.Errorf("list blob upload parts: %w", err)
	}
	defer rows.Close()

	var parts []UploadPart
	for rows.Next() {
		var part UploadPart
		if err = rows.Scan(
			&part.UploadID,
			&part.ChunkIndex,
			&part.ObjectKey,
			&part.SizeBytes,
			&part.ChecksumSHA256,
		); err != nil {
			return nil, fmt.Errorf("scan blob upload part: %w", err)
		}

		parts = append(parts, part)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blob upload parts: %w", err)
	}

	return parts, nil
}

// CommitUpload завершает upload session и создает blob metadata
func (r *PostgresRepository) CommitUpload(ctx context.Context, params CommitUploadParams) (Blob, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Blob{}, fmt.Errorf("begin commit blob upload tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	upload, err := findUploadByIDForUpdate(ctx, tx, params.UploadID)
	if err != nil {
		return Blob{}, err
	}

	if upload.UserID != params.UserID {
		return Blob{}, ErrAccessDenied
	}

	if upload.Status != UploadStatusCreated && upload.Status != UploadStatusUploading {
		return Blob{}, fmt.Errorf("%w: upload is not committable", ErrInvalidInput)
	}

	var actualChunks int32
	var actualSize int64
	err = tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)
		FROM blob_upload_parts
		WHERE upload_id = $1`,
		params.UploadID,
	).Scan(&actualChunks, &actualSize)
	if err != nil {
		return Blob{}, fmt.Errorf("count blob upload parts: %w", err)
	}

	if actualChunks != upload.ExpectedChunks || actualSize != upload.ExpectedSize {
		return Blob{}, ErrUploadIncomplete
	}

	var blobItem Blob
	err = tx.QueryRowContext(
		ctx,
		`INSERT INTO blobs (
			id,
			user_id,
			upload_id,
			status,
			storage_bucket,
			object_prefix,
			chunk_size,
			chunk_count,
			size_bytes,
			checksum_sha256
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING
			id,
			user_id,
			upload_id,
			status,
			storage_bucket,
			object_prefix,
			chunk_size,
			chunk_count,
			size_bytes,
			checksum_sha256`,
		params.BlobID,
		params.UserID,
		params.UploadID,
		BlobStatusReady,
		params.StorageBucket,
		params.ObjectPrefix,
		upload.ChunkSize,
		actualChunks,
		actualSize,
		params.ChecksumSHA256,
	).Scan(
		&blobItem.ID,
		&blobItem.UserID,
		&blobItem.UploadID,
		&blobItem.Status,
		&blobItem.StorageBucket,
		&blobItem.ObjectPrefix,
		&blobItem.ChunkSize,
		&blobItem.ChunkCount,
		&blobItem.SizeBytes,
		&blobItem.ChecksumSHA256,
	)
	if err != nil {
		return Blob{}, fmt.Errorf("create blob metadata: %w", err)
	}

	if _, err = tx.ExecContext(
		ctx,
		`UPDATE blob_uploads
		SET
			status = $2,
			received_chunks = $3,
			updated_at = NOW()
		WHERE id = $1`,
		params.UploadID,
		UploadStatusCommitted,
		actualChunks,
	); err != nil {
		return Blob{}, fmt.Errorf("mark blob upload committed: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return Blob{}, fmt.Errorf("commit blob upload tx: %w", err)
	}

	return blobItem, nil
}

// AbortUpload отменяет upload session
func (r *PostgresRepository) AbortUpload(ctx context.Context, params AbortUploadParams) error {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE blob_uploads
		SET
			status = $3,
			updated_at = NOW()
		WHERE id = $1
			AND user_id = $2
			AND status IN ($4, $5)`,
		params.UploadID,
		params.UserID,
		UploadStatusAborted,
		UploadStatusCreated,
		UploadStatusUploading,
	)
	if err != nil {
		return fmt.Errorf("abort blob upload: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check abort blob upload result: %w", err)
	}
	if rowsAffected == 0 {
		return ErrUploadNotFound
	}

	return nil
}

// FindBlobByID возвращает blob metadata по id
func (r *PostgresRepository) FindBlobByID(ctx context.Context, blobID string) (Blob, error) {
	var blobItem Blob

	err := r.db.QueryRowContext(
		ctx,
		`SELECT
			id,
			user_id,
			upload_id,
			status,
			storage_bucket,
			object_prefix,
			chunk_size,
			chunk_count,
			size_bytes,
			checksum_sha256
		FROM blobs
		WHERE id = $1
			AND deleted_at IS NULL`,
		blobID,
	).Scan(
		&blobItem.ID,
		&blobItem.UserID,
		&blobItem.UploadID,
		&blobItem.Status,
		&blobItem.StorageBucket,
		&blobItem.ObjectPrefix,
		&blobItem.ChunkSize,
		&blobItem.ChunkCount,
		&blobItem.SizeBytes,
		&blobItem.ChecksumSHA256,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Blob{}, ErrBlobNotFound
		}

		return Blob{}, fmt.Errorf("find blob metadata: %w", err)
	}

	return blobItem, nil
}

func findUploadByIDForUpdate(ctx context.Context, tx *sql.Tx, uploadID string) (Upload, error) {
	var upload Upload

	err := tx.QueryRowContext(
		ctx,
		`SELECT
			id,
			user_id,
			status,
			chunk_size,
			expected_size,
			expected_chunks,
			received_chunks,
			checksum_sha256,
			expires_at
		FROM blob_uploads
		WHERE id = $1
		FOR UPDATE`,
		uploadID,
	).Scan(
		&upload.ID,
		&upload.UserID,
		&upload.Status,
		&upload.ChunkSize,
		&upload.ExpectedSize,
		&upload.ExpectedChunks,
		&upload.ReceivedChunks,
		&upload.ChecksumSHA256,
		&upload.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Upload{}, ErrUploadNotFound
		}

		return Upload{}, fmt.Errorf("find blob upload for update: %w", err)
	}

	return upload, nil
}
