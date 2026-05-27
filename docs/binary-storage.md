# Binary и MinIO

Binary-секреты не хранят файл внутри vault item. Для файлов используется `BlobService` и MinIO.

## Почему так

Файл не стоит хранить как обычный encrypted payload внутри PostgreSQL:

- размер файла может быстро вырасти;
- PostgreSQL становится хранилищем больших объектов;
- streaming download/upload становится неудобным;
- лимит размера начинает зависеть от схемы хранения, а не от продуктового требования.

Поэтому проект использует object storage.

## Поток загрузки

```text
local file
  -> plaintext checksum
  -> split to chunks
  -> encrypt chunk by vault key
  -> CreateBlobUpload
  -> UploadBlob stream
  -> MinIO objects
  -> encrypted BinaryPayload with blob_id
  -> VaultService CreateItem or UpdateItem
```

## Поток скачивания

```text
VaultService GetItem
  -> decrypt BinaryPayload
  -> DownloadBlob stream by blob_id
  -> decrypt chunks
  -> join plaintext
  -> verify checksum
  -> write file
```

## Metadata

`BinaryPayload` хранит:

```json
{
  "file_name": "document.pdf",
  "content_type": "application/pdf",
  "size_bytes": 183244,
  "checksum_sha256": "plaintext-checksum",
  "blob_id": "uuid"
}
```

Этот JSON находится внутри encrypted vault payload. Сервер не видит пользовательское имя файла и plaintext checksum.

## Server storage

PostgreSQL:

- `blob_uploads`;
- `blob_upload_parts`;
- `blobs`.

MinIO:

- encrypted chunk objects.

## Настройки

```env
GOPHKEEPER_BLOB_STORAGE_ENABLED=true
GOPHKEEPER_MINIO_ENDPOINT=localhost:9000
GOPHKEEPER_MINIO_ACCESS_KEY=gophkeeper
GOPHKEEPER_MINIO_SECRET_KEY=gophkeeper-minio-password
GOPHKEEPER_MINIO_BUCKET=gophkeeper-blobs
GOPHKEEPER_MINIO_USE_SSL=false
GOPHKEEPER_BLOB_UPLOAD_TTL=24h
GOPHKEEPER_BLOB_CHUNK_SIZE=4194304
GOPHKEEPER_BLOB_MAX_SIZE=1073741824
```
