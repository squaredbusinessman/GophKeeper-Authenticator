# Серверное приложение

Сервер находится в `cmd/gophkeeper-server` и собирает инфраструктуру из `internal/server`.

## Основные компоненты

- `config` - загрузка env и валидация настроек.
- `database` - подключение к PostgreSQL.
- `migrations` - применение SQL-миграций.
- `grpcserver` - gRPC server, TLS и interceptors.
- `auth/register` - регистрация пользователя.
- `auth/login` - вход и выдача access token.
- `vault` - CRUD и sync vault items.
- `blob` - metadata и use cases для binary chunks.
- `blob/minio` - адаптер MinIO SDK к server blob storage.

## gRPC services

Сервер регистрирует:

- `AuthService`;
- `VaultService`;
- `BlobService`, если включен `GOPHKEEPER_BLOB_STORAGE_ENABLED=true`.

Protected методы требуют access token в gRPC metadata:

```text
authorization: Bearer <access-token>
```

## TLS

Сервер всегда использует TLS. Для локального запуска выполните `make certs` и передайте:

```env
GOPHKEEPER_GRPC_TLS_CERT_FILE=certs/server.crt
GOPHKEEPER_GRPC_TLS_KEY_FILE=certs/server.key
```

`grpc.NewServer` всегда получает `grpc.Creds`.

## Логирование

Сервер использует `go.uber.org/zap`.

Логи содержат:

- service name;
- gRPC method;
- status code;
- duration;
- user id для authenticated запросов.

Логи не должны содержать:

- пароль входа;
- мастер-пароль;
- access token;
- vault key;
- plaintext payload;
- ciphertext payload;
- OTP secret;
- binary chunks.

Ошибочные gRPC responses логируются на уровне `Warn` или `Error`, успешные responses - на `Info`.

## Консистентность vault

Vault items используют optimistic versioning:

- `create` создает новую запись;
- `update` требует `expected_version`;
- `delete` требует `expected_version`;
- конфликт версий возвращается как version conflict;
- удаление выполняется через soft delete и `deleted_at`.
