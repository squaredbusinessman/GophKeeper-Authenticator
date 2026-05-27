# GophKeeper Authenticator

GophKeeper Authenticator - учебный клиент-серверный менеджер секретов на Go, собранный как цельное приложение с CLI, TUI, gRPC API, PostgreSQL, MinIO и клиентским шифрованием.

Главное свойство проекта - сервер не получает пользовательские секреты в открытом виде. Клиент шифрует metadata, payload и binary chunks локально через vault key. Сервер хранит только encrypted bytes, технические версии, timestamps и служебные идентификаторы.

## Что реализовано

- Регистрация и вход с отдельным паролем входа и мастер-паролем.
- Vault key генерируется и расшифровывается только на клиенте.
- Типы секретов: text, login/password, bank card, binary и OTP.
- Binary-файлы сохраняются через `BlobService` и MinIO.
- OTP-коды считаются на клиенте по RFC 6238.
- CRUD и sync vault items через gRPC.
- CLI и TUI используют общий client app layer.
- OpenAPI-файл генерируется из protobuf HTTP mappings.
- Локальная инфраструктура запускается через Docker Compose.
- CI проверяет форматирование, vet, тесты, coverage, сборку CLI/TUI/server и smoke flow.

## Быстрый сценарий проверки

```bash
cp deploy/.env.example deploy/.env
docker compose -f deploy/docker-compose.yml up -d

set -a
source deploy/.env
set +a
go run ./cmd/gophkeeper-server
```

В другом терминале:

```bash
make tui
```

или:

```bash
go run ./cmd/gophkeeper-cli register
go run ./cmd/gophkeeper-cli create binary
```

## Основные разделы

- [Быстрый старт](quickstart.md) - как поднять проект локально.
- [Архитектура](architecture.md) - как связаны клиент, сервер, PostgreSQL и MinIO.
- [Безопасность](security.md) - модель client-side encryption и ограничения.
- [CLI](cli.md) - команды терминального клиента.
- [TUI](tui.md) - интерактивный терминальный клиент.
- [Binary и MinIO](binary-storage.md) - хранение файлов через encrypted chunks.
- [gRPC и protobuf](api.md) - контракт взаимодействия.
- [OpenAPI](openapi.md) - Swagger projection для проверки требований.
