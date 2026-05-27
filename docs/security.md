# Безопасность

Проект использует zero-knowledge подход для пользовательских секретов: сервер хранит encrypted data и не имеет ключей для расшифрования.

## Пароли

В проекте используются два разных секрета пользователя:

- пароль входа;
- мастер-пароль.

Пароль входа нужен для аутентификации на сервере. Мастер-пароль нужен для расшифрования vault key на клиенте.

Пароль входа и мастер-пароль не должны совпадать.

## Vault key

Vault key:

- создается на клиенте;
- имеет длину 32 bytes;
- используется для AES-256-GCM шифрования payload;
- не отправляется на сервер в открытом виде;
- хранится на сервере только как encrypted vault key metadata.

Если пользователь потерял мастер-пароль, восстановить vault key невозможно.

## Payload encryption

Payload шифруется через AES-256-GCM:

- для каждого шифрования создается новый nonce;
- integrity check встроен в AEAD;
- расшифрование падает при неверном ключе, поврежденном ciphertext или подмене nonce.

## Binary encryption

Binary-файл не отправляется на сервер как plaintext:

1. Клиент читает файл.
2. Клиент считает plaintext checksum.
3. Клиент режет файл на chunks.
4. Каждый chunk шифруется через vault key.
5. Сервер получает только encrypted chunks.

Plaintext checksum хранится внутри encrypted `BinaryPayload` и нужен клиенту для проверки результата после скачивания.

## TLS

Локальный dev-запуск может работать без TLS. Для production-like запуска gRPC TLS включается переменными:

```env
GOPHKEEPER_GRPC_TLS_ENABLED=true
GOPHKEEPER_GRPC_TLS_CERT_FILE=/path/to/server.crt
GOPHKEEPER_GRPC_TLS_KEY_FILE=/path/to/server.key
```

Клиентский TLS:

```env
GOPHKEEPER_SERVER_TLS_ENABLED=true
GOPHKEEPER_SERVER_TLS_CERT_FILE=/path/to/server.crt
```

## Логи

В логах не должно быть:

- паролей;
- access token;
- vault key;
- plaintext payload;
- ciphertext payload;
- OTP secret;
- binary chunks.
