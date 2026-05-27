-- +goose Up
-- +goose StatementBegin

-- blob_uploads хранит состояние незавершенных загрузок больших binary объектов
CREATE TABLE blob_uploads (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id UUID REFERENCES vault_items(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    chunk_size BIGINT NOT NULL,
    expected_size BIGINT NOT NULL,
    expected_chunks INTEGER NOT NULL,
    received_chunks INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT blob_uploads_status_check CHECK (status IN ('created', 'uploading', 'committed', 'aborted', 'expired')),
    CONSTRAINT blob_uploads_chunk_size_check CHECK (chunk_size > 0),
    CONSTRAINT blob_uploads_expected_size_check CHECK (expected_size > 0),
    CONSTRAINT blob_uploads_expected_chunks_check CHECK (expected_chunks > 0),
    CONSTRAINT blob_uploads_received_chunks_check CHECK (received_chunks >= 0)
);

COMMENT ON TABLE blob_uploads IS 'Незавершенные загрузки encrypted binary объектов';
COMMENT ON COLUMN blob_uploads.id IS 'Идентификатор upload session';
COMMENT ON COLUMN blob_uploads.user_id IS 'Идентификатор владельца upload session';
COMMENT ON COLUMN blob_uploads.item_id IS 'Идентификатор vault item после связывания с секретом';
COMMENT ON COLUMN blob_uploads.status IS 'Состояние upload session';
COMMENT ON COLUMN blob_uploads.chunk_size IS 'Размер chunk в байтах';
COMMENT ON COLUMN blob_uploads.expected_size IS 'Ожидаемый размер encrypted blob в байтах';
COMMENT ON COLUMN blob_uploads.expected_chunks IS 'Ожидаемое количество chunks';
COMMENT ON COLUMN blob_uploads.received_chunks IS 'Количество принятых chunks';
COMMENT ON COLUMN blob_uploads.created_at IS 'Дата и время создания upload session';
COMMENT ON COLUMN blob_uploads.updated_at IS 'Дата и время последнего изменения upload session';
COMMENT ON COLUMN blob_uploads.expires_at IS 'Дата и время истечения upload session';

CREATE TABLE blob_upload_parts (
    upload_id UUID NOT NULL REFERENCES blob_uploads(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    object_key TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (upload_id, chunk_index),
    CONSTRAINT blob_upload_parts_chunk_index_check CHECK (chunk_index >= 0),
    CONSTRAINT blob_upload_parts_size_bytes_check CHECK (size_bytes > 0)
);

COMMENT ON TABLE blob_upload_parts IS 'Chunks, принятые в рамках upload session';
COMMENT ON COLUMN blob_upload_parts.upload_id IS 'Идентификатор upload session';
COMMENT ON COLUMN blob_upload_parts.chunk_index IS 'Порядковый номер chunk';
COMMENT ON COLUMN blob_upload_parts.object_key IS 'Ключ объекта в MinIO';
COMMENT ON COLUMN blob_upload_parts.size_bytes IS 'Размер encrypted chunk в байтах';
COMMENT ON COLUMN blob_upload_parts.checksum_sha256 IS 'SHA256 checksum encrypted chunk';
COMMENT ON COLUMN blob_upload_parts.created_at IS 'Дата и время сохранения chunk';

CREATE TABLE blobs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id UUID REFERENCES vault_items(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    storage_bucket TEXT NOT NULL,
    object_prefix TEXT NOT NULL,
    chunk_size BIGINT NOT NULL,
    chunk_count INTEGER NOT NULL,
    size_bytes BIGINT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT blobs_status_check CHECK (status IN ('ready', 'deleted')),
    CONSTRAINT blobs_chunk_size_check CHECK (chunk_size > 0),
    CONSTRAINT blobs_chunk_count_check CHECK (chunk_count > 0),
    CONSTRAINT blobs_size_bytes_check CHECK (size_bytes > 0)
);

COMMENT ON TABLE blobs IS 'Metadata постоянных encrypted binary объектов';
COMMENT ON COLUMN blobs.id IS 'Идентификатор blob';
COMMENT ON COLUMN blobs.user_id IS 'Идентификатор владельца blob';
COMMENT ON COLUMN blobs.item_id IS 'Идентификатор vault item, который ссылается на blob';
COMMENT ON COLUMN blobs.status IS 'Состояние blob';
COMMENT ON COLUMN blobs.storage_bucket IS 'Bucket object storage';
COMMENT ON COLUMN blobs.object_prefix IS 'Префикс объектов blob в MinIO';
COMMENT ON COLUMN blobs.chunk_size IS 'Размер chunk в байтах';
COMMENT ON COLUMN blobs.chunk_count IS 'Количество chunks';
COMMENT ON COLUMN blobs.size_bytes IS 'Полный размер encrypted blob в байтах';
COMMENT ON COLUMN blobs.checksum_sha256 IS 'SHA256 checksum encrypted blob или manifest checksum';
COMMENT ON COLUMN blobs.created_at IS 'Дата и время создания blob';
COMMENT ON COLUMN blobs.deleted_at IS 'Дата и время soft delete blob';

CREATE INDEX idx_blob_uploads_user_status
    ON blob_uploads(user_id, status);

CREATE INDEX idx_blob_uploads_expires_at
    ON blob_uploads(expires_at);

CREATE INDEX idx_blobs_user_status
    ON blobs(user_id, status);

CREATE INDEX idx_blobs_item_id
    ON blobs(item_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_blobs_item_id;
DROP INDEX IF EXISTS idx_blobs_user_status;
DROP INDEX IF EXISTS idx_blob_uploads_expires_at;
DROP INDEX IF EXISTS idx_blob_uploads_user_status;

DROP TABLE IF EXISTS blobs;
DROP TABLE IF EXISTS blob_upload_parts;
DROP TABLE IF EXISTS blob_uploads;

-- +goose StatementEnd
