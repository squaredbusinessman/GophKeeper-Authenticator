# Архитектура

GophKeeper Authenticator разделен на клиентскую и серверную части.

```text
CLI/TUI
  -> client app runtime
  -> client core
  -> gRPC
  -> server grpc handlers
  -> use cases
  -> PostgreSQL
  -> MinIO для binary chunks
```

## Клиент

Клиент отвечает за:

- ввод пользовательских данных;
- derivation vault key из мастер-пароля;
- шифрование metadata и payload;
- генерацию OTP-кодов;
- разбиение binary-файла на chunks;
- шифрование binary chunks;
- проверку plaintext checksum после скачивания файла.

CLI и TUI используют общий client core, поэтому правила безопасности и форматы payload совпадают.

## Сервер

Сервер отвечает за:

- регистрацию и вход;
- выпуск JWT access token;
- проверку access token в interceptors;
- хранение encrypted vault items;
- optimistic versioning;
- soft delete;
- sync изменений;
- upload/download encrypted binary chunks.

Сервер не расшифровывает пользовательские данные.

## Хранилища

PostgreSQL хранит:

- пользователей;
- password hash;
- encrypted vault key metadata;
- vault items;
- blob upload sessions;
- blob parts;
- blob metadata.

MinIO хранит:

- encrypted binary chunk objects.

## Поток регистрации

```text
user input
  -> client validates passwords
  -> client generates vault key
  -> client encrypts vault key by master password
  -> server stores user and encrypted vault key metadata
  -> server returns access token
```

## Поток создания секрета

```text
user input
  -> client encodes payload schema
  -> client encrypts metadata and payload
  -> gRPC CreateItem
  -> server stores encrypted item
```

## Поток binary-секрета

```text
file
  -> plaintext checksum
  -> chunking
  -> encrypt each chunk
  -> BlobService UploadBlob stream
  -> MinIO encrypted objects
  -> VaultService item with encrypted BinaryPayload and blob_id
```
