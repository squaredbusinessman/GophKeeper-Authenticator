# gRPC и protobuf

Основной runtime transport проекта - gRPC. Контракт описан в Protocol Buffers:

```text
api/proto/gophkeeper/v1/gophkeeper.proto
```

Сгенерированный Go-код находится в:

```text
internal/gen/proto/gophkeeper/v1
```

## Services

### AuthService

- `Register` - создает пользователя, сохраняет encrypted vault key metadata и возвращает access token.
- `Login` - проверяет пароль входа, возвращает access token и encrypted vault key metadata.

### VaultService

- `CreateItem` - создает vault item.
- `GetItem` - возвращает один item по id.
- `ListItems` - возвращает активные items.
- `UpdateItem` - обновляет item с проверкой expected version.
- `DeleteItem` - выполняет soft delete с проверкой expected version.
- `Sync` - возвращает изменения и tombstones.

### BlobService

- `CreateBlobUpload` - создает upload session.
- `UploadBlob` - принимает encrypted chunks через client streaming.
- `DownloadBlob` - отдает encrypted chunks через server streaming.
- `AbortBlobUpload` - отменяет upload session.

## Item types

Поддерживаются типы:

- `ITEM_TYPE_TEXT`;
- `ITEM_TYPE_LOGIN_PASSWORD`;
- `ITEM_TYPE_BANK_CARD`;
- `ITEM_TYPE_BINARY`;
- `ITEM_TYPE_OTP`.

## Генерация

```bash
make proto
```

Команда запускает генерацию protobuf Go-кода и OpenAPI-файла.

Отдельная генерация OpenAPI:

```bash
make generate-openapi
```
