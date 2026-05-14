# GophKeeper

GophKeeper - клиент-серверный менеджер секретов для безопасного хранения приватных данных пользователя.

Проект разрабатывается как выпускной проект. Основная цель - реализовать надежное ядро менеджера секретов с gRPC API, PostgreSQL, CLI-клиентом, клиентским шифрованием и синхронизацией данных между несколькими устройствами одного пользователя.

## Статус проекта

Проект находится в активной разработке.

На текущем этапе уже подготовлены:

- базовая структура Go-проекта;
- команда версии CLI;
- загрузка конфигурации сервера и клиента из переменных окружения;
- начальные gRPC proto-контракты;
- генерация Go-кода из proto через EasyP;
- bootstrap gRPC-сервера;
- graceful shutdown серверного приложения;
- структурный logging через `go.uber.org/zap`;
- локальный PostgreSQL в Docker Compose.

Часть команд ниже описывает уже рабочий сценарий, часть команд помечена как планируемая и будет уточняться по мере реализации бизнес-логики.

## Что должен уметь GophKeeper

GophKeeper должен поддерживать хранение:

- пар логин и пароль;
- произвольных текстовых секретов;
- произвольных бинарных данных;
- данных банковских карт;
- произвольной текстовой метаинформации для любого элемента.

Обязательное ядро MVP:

- gRPC API;
- PostgreSQL;
- Docker Compose для локального запуска;
- регистрация и вход пользователя;
- auth middleware;
- client-side encryption;
- CRUD секретов;
- version-based sync;
- CLI;
- unit-тесты с покрытием не менее 70%;
- README с инструкциями запуска и проверки;
- отображение версии и даты сборки CLI.

Расширения после надежного MVP:

- refresh token flow;
- OTP/TOTP;
- TUI;
- MinIO или S3-compatible blob storage;
- gRPC streaming для больших бинарных файлов;
- Swagger/OpenAPI через gRPC-Gateway;
- offline/cache режим через SQLite;
- GUI через Wails.

## Архитектура

Проект состоит из следующих частей:

- `cmd/gophkeeper-cli` - CLI-клиент;
- `cmd/gophkeeper-server` - серверное приложение;
- `api/proto` - gRPC proto-контракты;
- `internal/gen/proto` - сгенерированный Go-код protobuf и gRPC;
- `internal/client` - будущая клиентская бизнес-логика;
- `internal/server` - серверная логика и инфраструктура;
- `internal/shared` - общие пакеты;
- `deploy` - локальная инфраструктура для разработки и проверки;
- `migrations` - будущие SQL-миграции.

Основной протокол взаимодействия клиента и сервера - gRPC.

Для MVP `.proto` файлы являются главным описанием API. Swagger/OpenAPI через gRPC-Gateway можно добавить позже, если основной сценарий будет реализован надежно.

Серверная база данных - PostgreSQL. SQLite не используется на сервере. SQLite может появиться только на стороне клиента для будущего offline/cache режима.

## Client core и интерфейсы

Клиентская часть должна быть разделена на business core и presentation layers.

```text
client core
- auth use cases
- vault use cases
- sync logic
- client-side crypto
- token storage
- grpc client

presentation layers
- CLI
- TUI
- потенциальный GUI через Wails
```

CLI, TUI и будущий GUI не должны содержать бизнес-логику, напрямую шифровать данные, напрямую работать с token storage или ходить в gRPC API в обход client core.

Такой подход нужен, чтобы позже добавить TUI или GUI без переписывания клиентской бизнес-логики.

## Модель безопасности

GophKeeper проектируется как zero-knowledge/client-side encryption система.

Сервер хранит encrypted payload и технические метаданные. Сервер не должен иметь доступа к пользовательским секретам в открытом виде.

### Пароль входа и мастер-пароль

В системе используются два разных пароля:

1. Пароль входа.
2. Мастер-пароль.

Пароль входа используется только для аутентификации на сервере.

Мастер-пароль используется локально на клиенте для открытия зашифрованного хранилища.

Важно:

- пароль входа и мастер-пароль должны отличаться;
- мастер-пароль не отправляется на сервер;
- мастер-пароль не хранится на сервере;
- мастер-пароль не должен храниться на клиенте в открытом виде;
- если мастер-пароль потерян, восстановить сохраненные секреты невозможно.

### Vault key

Для поддержки нескольких устройств используется схема с `vault key`.

```text
master password
    -> KDF
key-encryption key
    -> decrypt
vault key
    -> encrypt/decrypt
user secrets
```

`vault key` генерируется криптостойко один раз на клиенте. На сервере он хранится только в зашифрованном виде. Клиент расшифровывает `vault key` через ключ, полученный из мастер-пароля.

Сервер не знает:

- мастер-пароль;
- key-encryption key;
- vault key;
- пользовательские секреты в открытом виде.

### Восстановление доступа

Если пользователь потерял мастер-пароль, восстановить секреты невозможно.

Это ожидаемое ограничение zero-knowledge модели. Сервер не может помочь восстановить доступ, потому что не имеет ключей для расшифрования пользовательских данных.

### TLS

Для локальной проверки допускается dev-режим без TLS.

Dev-режим без TLS предназначен только для запуска на локальной машине. Его нельзя использовать для сетевого или production-like развертывания.

Для production-like режима нужен TLS, потому что пароль входа, access token и gRPC metadata не должны передаваться по незащищенному каналу.

## Синхронизация

Для MVP используется online-first подход.

Основные правила:

- сервер является источником истины;
- каждый элемент хранилища имеет `version`;
- update и delete требуют `expected_version`;
- если версия не совпала, сервер должен вернуть conflict;
- удаление выполняется как soft delete через `deleted_at`;
- tombstones должны участвовать в синхронизации между клиентами.

Полноценный offline-режим в MVP не входит. Локальное шифрованное хранилище, очередь изменений, retry и replay изменений можно добавить позже.

## Бинарные данные

Для MVP небольшие бинарные данные могут храниться inline в PostgreSQL как encrypted payload.

Планируемые ограничения MVP:

- явный лимит размера payload;
- file metadata хранится в зашифрованном виде;
- слишком большие файлы отклоняются понятной ошибкой;
- поиск по пользовательским file metadata выполняется на клиенте после расшифрования.

MinIO, chunking, checksums и gRPC streaming остаются расширениями после MVP.

## Требования для локального запуска

Для разработки и проверки нужны:

- Go toolchain версии, указанной в `go.mod`;
- Docker;
- Docker Compose;
- терминал на macOS, Linux или Windows.

Проверяющий не должен вручную устанавливать PostgreSQL или подключать внешние managed-сервисы.

## Переменные окружения

Пример локальных переменных для Docker лежит в:

```text
deploy/.env.example
```

Создать локальный `.env` для Docker можно так:

```bash
cp deploy/.env.example deploy/.env
```

Текущие значения для PostgreSQL:

```env
POSTGRES_DB=gophkeeper
POSTGRES_USER=gophkeeper
POSTGRES_PASSWORD=gophkeeper
POSTGRES_PORT=5432

GOPHKEEPER_DATABASE_DSN=postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable
```

Файл `deploy/.env` предназначен для локальной машины и не должен содержать production secrets.

## Локальный PostgreSQL через Docker Compose

Запуск PostgreSQL:

```bash
docker compose -f deploy/docker-compose.yml up -d
```

Проверка контейнера:

```bash
docker compose -f deploy/docker-compose.yml ps
```

Проверка готовности PostgreSQL:

```bash
docker compose -f deploy/docker-compose.yml exec postgres pg_isready -U gophkeeper -d gophkeeper
```

Просмотр логов PostgreSQL:

```bash
docker compose -f deploy/docker-compose.yml logs -f postgres
```

Остановка контейнера без удаления данных:

```bash
docker compose -f deploy/docker-compose.yml stop
```

Остановка и удаление контейнера:

```bash
docker compose -f deploy/docker-compose.yml down
```

Полная очистка локальных данных PostgreSQL:

```bash
docker compose -f deploy/docker-compose.yml down -v
```

## Запуск gRPC-сервера

Сейчас сервер умеет стартовать, регистрировать gRPC-сервисы и корректно завершаться по `SIGINT` или `SIGTERM`.

Серверные handlers пока являются заглушками через `Unimplemented...Server`. Это нормально для bootstrap-этапа: транспортный слой уже поднимается, а бизнес-логика будет добавляться следующими шагами.

Перед запуском сервера нужно передать обязательные переменные окружения:

```bash
GOPHKEEPER_DATABASE_DSN='postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable' \
GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-secret-change-me' \
go run ./cmd/gophkeeper-server
```

По умолчанию сервер слушает:

```text
:9090
```

Переопределить адрес можно так:

```bash
GOPHKEEPER_GRPC_ADDRESS=':9091' \
GOPHKEEPER_DATABASE_DSN='postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable' \
GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-secret-change-me' \
go run ./cmd/gophkeeper-server
```

Ожидаемый результат при старте - JSON-лог от `zap` с полями `service`, `address` и `tls_enabled`.

Остановить сервер можно через `Ctrl+C`.

## CLI

Сейчас реализована команда версии.

Запуск через Go:

```bash
go run ./cmd/gophkeeper-cli version
```

Сборка CLI:

```bash
go build -o ./bin/gophkeeper ./cmd/gophkeeper-cli
```

Проверка версии собранного бинарного файла:

```bash
./bin/gophkeeper version
```

Планируемые команды CLI:

```text
gophkeeper version
gophkeeper register
gophkeeper login
gophkeeper logout
gophkeeper list
gophkeeper get
gophkeeper create
gophkeeper update
gophkeeper delete
gophkeeper sync
```

Секретные значения не должны передаваться через CLI flags, потому что они могут попасть в shell history. Для чувствительных данных нужно использовать скрытый prompt или безопасный ввод через файл.

## Сборка версии CLI

CLI должен показывать:

- версию;
- дату сборки;
- commit hash, если он передан при сборке.

Текущая dev-команда:

```bash
go run ./cmd/gophkeeper-cli version
```

Планируемая сборка с `ldflags`:

```bash
go build \
  -ldflags "-X github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version.Version=dev -X github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version.Commit=$(git rev-parse --short HEAD)" \
  -o ./bin/gophkeeper \
  ./cmd/gophkeeper-cli
```

## Proto и gRPC code generation

Proto-контракты находятся в:

```text
api/proto/gophkeeper/v1/gophkeeper.proto
```

Сгенерированный Go-код находится в:

```text
internal/gen/proto/gophkeeper/v1
```

Проверка EasyP-конфига:

```bash
easyp validate-config
```

Lint proto-контрактов:

```bash
easyp lint --root api/proto --path .
```

Генерация Go-кода:

```bash
easyp generate
```

Сгенерированный код коммитится в репозиторий, чтобы проверяющему не нужно было обязательно устанавливать EasyP для обычной сборки проекта.

## Тестирование

Запуск всех тестов:

```bash
go test ./...
```

Планируемая проверка покрытия:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

Целевое покрытие проекта unit-тестами - не менее 70%.

Наиболее важные зоны тестирования:

- password hashing;
- password verification;
- key derivation;
- шифрование и расшифрование vault key;
- шифрование и расшифрование секретов;
- auth use cases;
- vault use cases;
- обработка version conflicts;
- преобразование доменных ошибок в gRPC status codes;
- поведение CLI-команд через fake client core.

Generated protobuf code напрямую тестировать не планируется.

## Локальный smoke-сценарий на текущем этапе

Пока бизнес-логика регистрации и хранилища не реализована, минимальная проверка выглядит так:

```bash
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml ps
go test ./...
go run ./cmd/gophkeeper-cli version
GOPHKEEPER_DATABASE_DSN='postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable' GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-secret-change-me' go run ./cmd/gophkeeper-server
```

После запуска сервера нажать `Ctrl+C` и убедиться, что приложение завершилось без panic.

## Будущий приемочный сценарий

Когда бизнес-логика будет реализована, проверяющий должен иметь возможность выполнить один локальный сценарий:

```bash
docker compose -f deploy/docker-compose.yml up -d
go test ./...
go build -o ./bin/gophkeeper ./cmd/gophkeeper-cli
./bin/gophkeeper version
./bin/gophkeeper register
./bin/gophkeeper login
./bin/gophkeeper create
./bin/gophkeeper list
./bin/gophkeeper get
./bin/gophkeeper update
./bin/gophkeeper delete
./bin/gophkeeper sync
docker compose -f deploy/docker-compose.yml down
```

Команды `register`, `login`, `create`, `list`, `get`, `update`, `delete` и `sync` пока являются целевым интерфейсом и будут уточняться при реализации CLI.

## Разработка

Проект реализуется через короткие задачи и небольшие коммиты.

Рекомендуемый порядок MVP:

1. Локальная инфраструктура и bootstrap сервера.
2. Схема БД и миграции.
3. Регистрация и вход.
4. Auth middleware.
5. Client-side crypto.
6. CRUD секретов.
7. Version-based sync.
8. CLI поверх client core.
9. Тесты, документация и финальная приемочная проверка.

Опциональные функции не должны блокировать надежный основной сценарий.

## Модель угроз

GophKeeper должен защищать от:

- утечки серверной базы данных;
- доступа администратора сервера к encrypted payload;
- чтения серверных backup-файлов без мастер-пароля;
- синхронизации ciphertext между устройствами без раскрытия plaintext серверу;
- перехвата сетевого трафика при корректно настроенном TLS.

GophKeeper не защищает от:

- malware на клиентской машине;
- keylogger на клиентской машине;
- слабого мастер-пароля;
- потери мастер-пароля;
- чтения данных, уже расшифрованных в памяти процесса;
- утечки секретов через shell history.

Практическое следствие: пользовательские секреты не нужно передавать как аргументы командной строки.
