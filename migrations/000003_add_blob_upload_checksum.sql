-- +goose Up
-- +goose StatementBegin

ALTER TABLE blob_uploads
    ADD COLUMN IF NOT EXISTS checksum_sha256 TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN blob_uploads.checksum_sha256 IS 'SHA256 checksum encrypted blob';

ALTER TABLE blob_uploads
    ALTER COLUMN checksum_sha256 DROP DEFAULT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE blob_uploads
    DROP COLUMN IF EXISTS checksum_sha256;

-- +goose StatementEnd
