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
- локальный PostgreSQL в Docker Compose;
- Argon2id hash и verify для пароля входа;
- генерация и шифрование vault key на клиентской стороне;
- шифрование payload секретов на клиентской стороне;
- серверный use case регистрации с сохранением пользователя и encrypted vault key metadata;
- gRPC `Register`;
- серверный use case входа;
- JWT access token с TTL;
- gRPC `Login` с возвратом access token и encrypted vault key metadata;
- auth middleware для protected gRPC-методов;
- серверные use cases для create, get, list, update, delete и sync vault items;
- gRPC Vault API для create, get, list, update, delete и sync;
- client core для auth flow, vault flow и sync flow;
- CLI-команды `register`, `login`, `create`, `get`, `list`, `update`, `delete`, `sync`;
- typed client payload schemas для `login_password`, `text`, `bank_card`, `binary` и `otp`;
- TOTP генерация по RFC 6238 на стороне клиента;
- TUI-клиент для auth flow и операций с vault;
- inline binary metadata, checksum и size limit;
- Swagger/OpenAPI описание gRPC HTTP projection;
- coverage gate в CI с порогом не ниже 70%;
- кроссплатформенная сборка CLI под Linux, macOS и Windows.

Команды ниже описывают рабочий сценарий текущего состояния проекта.

## Что должен уметь GophKeeper

GophKeeper должен поддерживать хранение:

- пар логин и пароль;
- произвольных текстовых секретов;
- произвольных бинарных данных;
- данных банковских карт;
- OTP-секретов для одноразовых паролей;
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
- TUI;
- Swagger/OpenAPI описание протокола;
- unit-тесты с покрытием не менее 70%;
- README с инструкциями запуска и проверки;
- отображение версии и даты сборки CLI.

## Архитектура

Проект состоит из следующих частей:

- `cmd/gophkeeper-cli` - CLI-клиент;
- `cmd/gophkeeper-server` - серверное приложение;
- `api/proto` - gRPC proto-контракты;
- `internal/gen/proto` - сгенерированный Go-код protobuf и gRPC;
- `api/openapi` - Swagger/OpenAPI описание HTTP projection gRPC-контракта;
- `internal/client` - клиентская бизнес-логика и client-side crypto;
- `internal/server` - серверная логика и инфраструктура;
- `internal/shared` - общие пакеты;
- `deploy` - локальная инфраструктура для разработки и проверки;
- `migrations` - SQL-миграции базы данных.

Основной runtime-протокол взаимодействия клиента и сервера - gRPC.

Swagger/OpenAPI файл описывает HTTP projection того же protobuf-контракта для выполнения требования ТЗ по документированию протокола. Сервер проекта не переключается на REST и не использует OpenAPI как runtime transport.

Серверная база данных - PostgreSQL. SQLite не используется на сервере и не входит в текущую реализацию клиента.

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
```

CLI и TUI не содержат бизнес-логику, напрямую не шифруют данные, напрямую не работают с token storage и не ходят в gRPC API в обход client core.

Такой подход отделяет presentation layer от client core и фиксирует единый путь работы с auth, vault, sync и client-side encryption.

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

### Хеширование пароля входа

Пароль входа не хранится в открытом виде.

Для серверного хеширования пароля входа используется Argon2id. Реализация находится в:

```text
internal/server/auth/password
```

Argon2id выбран потому что он устойчивее к перебору на GPU и ASIC, чем простые быстрые хеш-функции вроде SHA-256. Для паролей нельзя использовать быстрые хеши напрямую, потому что атакующий сможет проверять слишком много вариантов в секунду при утечке базы данных.

Почему не SHA-256:

- SHA-256 слишком быстрый для password hashing;
- у него нет встроенной соли и параметров стоимости;
- он не создает заметной вычислительной цены для brute force атаки.

Почему не bcrypt:

- bcrypt остается допустимым вариантом, но ограничен по работе с памятью;
- Argon2id позволяет настраивать и CPU cost, и memory cost;
- memory-hard свойства Argon2id лучше подходят для защиты от массового перебора.

Формат сохраненного хеша похож на PHC string:

```text
$argon2id$v=19$m=65536,t=3,p=4$base64salt$base64hash
```

В одной строке хранятся:

- алгоритм;
- версия Argon2;
- параметры KDF;
- соль;
- итоговый hash.

Это позволяет менять параметры и при этом проверять старые хеши с теми параметрами, с которыми они были созданы.

### Регистрация и вход

Регистрация и вход реализуются на сервере в пакетах:

```text
internal/server/auth/register
internal/server/auth/login
internal/server/grpcserver/handler
```

`Register` принимает login, пароль входа и encrypted vault key metadata, подготовленные клиентом. Сервер:

1. Проверяет обязательные поля запроса.
2. Хеширует пароль входа через Argon2id.
3. Создает пользователя.
4. Сохраняет encrypted vault key metadata в `user_vaults`.
5. Проверяет уникальность login через PostgreSQL unique constraint.

Пользователь и vault создаются атомарно в одной транзакции. Это важно, потому что пользователь без encrypted vault key был бы некорректным состоянием: аккаунт уже есть, но открыть хранилище невозможно.

`Login` принимает login и пароль входа. Сервер:

1. Находит пользователя по login.
2. Получает сохраненный password hash и encrypted vault key metadata.
3. Проверяет пароль входа через Argon2id verify.
4. Выпускает JWT access token.
5. Возвращает access token, срок действия token и encrypted vault key metadata.

Если login не найден или пароль неверный, наружу возвращается единая ошибка неверных учетных данных. Это сделано намеренно, чтобы API не помогал перебирать существующие login.

### Access token

Для доступа к защищенным gRPC-методам используется JWT access token.

Реализация находится в:

```text
internal/server/auth/token
```

Token подписывается через HMAC SHA-256 (`HS256`) с секретом из переменной окружения:

```text
GOPHKEEPER_ACCESS_TOKEN_SECRET
```

Минимальная длина секрета: 32 символа.

Срок действия token задается через:

```text
GOPHKEEPER_ACCESS_TOKEN_TTL
```

По умолчанию token живет 5 минут.

JWT содержит стандартные claims:

- `sub` - идентификатор пользователя;
- `exp` - время истечения token;
- `iat` - время выпуска token.

Почему JWT:

- token можно проверять без обращения к базе данных;
- формат стандартный и хорошо поддерживается в Go;
- JWT удобно передавать в gRPC metadata;
- подпись защищает claims от незаметной подмены.

В текущей реализации используется только access token.

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

### Шифрование vault key

Шифрование `vault key` реализуется на клиентской стороне в пакете:

```text
internal/client/crypto/vaultkey
```

Схема работы:

1. Клиент генерирует случайный `vault key` длиной 32 байта.
2. Пользователь вводит мастер-пароль.
3. Из мастер-пароля через Argon2id получается `key-encryption key`.
4. `vault key` шифруется через XChaCha20-Poly1305.
5. Сервер получает и хранит только encrypted vault key, nonce и KDF metadata.

Argon2id используется здесь не для хранения пароля, а для получения ключа шифрования из мастер-пароля. Это разные задачи, но обе требуют KDF, устойчивой к перебору.

Для шифрования выбран XChaCha20-Poly1305.

Почему XChaCha20-Poly1305:

- это AEAD-алгоритм, который одновременно обеспечивает конфиденциальность и контроль целостности;
- он хорошо подходит для кроссплатформенного CLI;
- он не требует аппаратного AES-ускорения;
- он использует nonce большего размера, чем обычный ChaCha20-Poly1305;
- большой nonce снижает риск случайного повторного использования nonce.

Почему не AES-GCM:

- AES-GCM тоже является хорошим AEAD-вариантом;
- на некоторых машинах он особенно эффективен при наличии AES-NI;
- но для CLI под macOS, Linux и Windows XChaCha20-Poly1305 дает более ровное поведение на разных платформах;
- XChaCha20-Poly1305 менее чувствителен к случайной генерации nonce благодаря 24-байтовому nonce.

Что важно для безопасности:

- мастер-пароль не логируется;
- key-encryption key не сохраняется;
- vault key в открытом виде не отправляется на сервер;
- encrypted vault key можно хранить на сервере;
- без мастер-пароля расшифровать encrypted vault key нельзя.

### Шифрование payload секретов

Шифрование пользовательских секретов реализуется на клиентской стороне в пакете:

```text
internal/client/crypto/payload
```

Payload в этом контексте это содержимое конкретной записи хранилища: текстовый секрет, логин и пароль, банковская карта или бинарные данные. Перед отправкой на сервер клиент должен превратить эти данные в bytes и зашифровать их через `vault key`.

Для payload используется AES-256-GCM из стандартной библиотеки Go. Ключом выступает `vault key` длиной 32 байта. Для каждой операции шифрования генерируется новый nonce через `crypto/rand`.

Почему AES-GCM:

- это AEAD-режим, который одновременно дает шифрование и проверку целостности;
- он доступен в стандартной библиотеке Go без дополнительных зависимостей;
- он хорошо подходит для небольших payload, которые MVP хранит inline в PostgreSQL;
- при неверном ключе, поврежденном ciphertext или подмененном nonce расшифровка завершается ошибкой.

Сервер не получает пользовательский payload в открытом виде. Он хранит только ciphertext, nonce, тип секрета и техническую metadata.

### OTP модель

OTP-секрет хранится как обычный encrypted vault item с типом `ITEM_TYPE_OTP`.

Plaintext payload существует только на клиенте до шифрования и после расшифрования:

```json
{
  "issuer": "Example",
  "account_name": "user@example.com",
  "secret": "BASE32SECRET",
  "algorithm": "SHA1",
  "digits": 6,
  "period_seconds": 30,
  "notes": "optional"
}
```

Клиент валидирует OTP payload, кодирует его в JSON и шифрует через vault key. Сервер хранит encrypted payload, encrypted metadata, тип `ITEM_TYPE_OTP`, версию схемы и технические timestamps. Сервер не получает plaintext OTP secret и не может рассчитать одноразовый код.

TOTP-код рассчитывается на клиенте по RFC 6238. Поддерживаются алгоритмы `SHA1`, `SHA256`, `SHA512`, длина кода `6` или `8` цифр и период ротации больше нуля. Значение периода по умолчанию - 30 секунд.

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

Полноценный offline-режим в MVP не входит. Текущая реализация синхронизации работает через online gRPC API.

## Бинарные данные

Для MVP небольшие бинарные данные могут храниться inline в PostgreSQL как encrypted payload.

Текущие ограничения MVP:

- явный лимит размера payload;
- file metadata хранится в зашифрованном виде;
- checksum хранится в зашифрованном payload и проверяется на клиенте;
- слишком большие файлы отклоняются понятной ошибкой;
- поиск по пользовательским file metadata выполняется на клиенте после расшифрования.

MinIO, chunking и gRPC streaming остаются расширениями после MVP.

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
GOPHKEEPER_LOG_MODE=dev
```

Файл `deploy/.env` предназначен для локальной машины и не должен содержать production secrets.

### Server env

Сервер читает следующие переменные окружения:

```env
GOPHKEEPER_GRPC_ADDRESS=:9090
GOPHKEEPER_GRPC_TLS_ENABLED=false
GOPHKEEPER_GRPC_TLS_CERT_FILE=
GOPHKEEPER_GRPC_TLS_KEY_FILE=
GOPHKEEPER_DATABASE_DSN=postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable
GOPHKEEPER_ACCESS_TOKEN_SECRET=local-dev-access-token-secret-32-bytes
GOPHKEEPER_ACCESS_TOKEN_TTL=5m
GOPHKEEPER_MIGRATIONS_ENABLED=true
GOPHKEEPER_MIGRATIONS_DIR=migrations
GOPHKEEPER_DATABASE_PING_TTL=5s
GOPHKEEPER_LOG_MODE=dev
```

TLS включается через `GOPHKEEPER_GRPC_TLS_ENABLED=true`. В этом режиме обязательны `GOPHKEEPER_GRPC_TLS_CERT_FILE` и `GOPHKEEPER_GRPC_TLS_KEY_FILE`.

`GOPHKEEPER_LOG_MODE` управляет форматом логов сервера:

- `dev` - цветной console output для локальной разработки;
- `prod` - JSON output для CI и production-like запуска.

### Client env для CLI и TUI

CLI и TUI используют общий client app layer и читают одинаковые переменные окружения:

```env
GOPHKEEPER_SERVER_ADDRESS=localhost:9090
GOPHKEEPER_SERVER_TLS_ENABLED=false
GOPHKEEPER_SERVER_TLS_CERT_FILE=
GOPHKEEPER_TOKEN_FILE=$HOME/.gophkeeper/token.json
```

TLS-клиент включается через `GOPHKEEPER_SERVER_TLS_ENABLED=true`. В этом режиме обязательна переменная `GOPHKEEPER_SERVER_TLS_CERT_FILE` с путем к server certificate.

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

Сейчас сервер умеет стартовать, подключаться к PostgreSQL, применять миграции, регистрировать gRPC-сервисы и корректно завершаться по `SIGINT` или `SIGTERM`.

В `AuthService` реализованы `Register` и `Login`. В `VaultService` реализованы protected методы `CreateItem`, `GetItem`, `ListItems`, `UpdateItem`, `DeleteItem` и `Sync`.

Перед запуском сервера нужно передать обязательные переменные окружения:

```bash
GOPHKEEPER_DATABASE_DSN='postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable' \
GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-access-token-secret-32-bytes' \
GOPHKEEPER_LOG_MODE='dev' \
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
GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-access-token-secret-32-bytes' \
GOPHKEEPER_LOG_MODE='dev' \
go run ./cmd/gophkeeper-server
```

Ожидаемый результат при старте в `dev` режиме - цветной console log от `zap` с полями `service`, `address` и `tls_enabled`.

После каждого unary gRPC-запроса сервер пишет access-log:

```text
grpc request completed
```

В нем есть:

- `grpc_method` - полный gRPC-метод;
- `grpc_code` - итоговый status code;
- `duration` - время обработки запроса;
- `user_id` - только для запросов, где пользователь уже аутентифицирован.

Сервер не логирует request body, пароли, access token, vault key, payload, ciphertext и данные секретов. Это важно, потому что логи часто попадают в CI, терминал, файлы или внешние системы наблюдаемости.

Остановить сервер можно через `Ctrl+C`.

## TUI

TUI запускается поверх того же client core, что и CLI. В TUI нет прямой gRPC-логики и client-side crypto логики.

Перед запуском TUI должен быть запущен PostgreSQL и gRPC-сервер.

Запуск через Makefile:

```bash
make tui
```

Запуск через Go:

```bash
go run ./cmd/gophkeeper-tui
```

Сборка TUI:

```bash
make build-tui
./bin/gophkeeper-tui
```

Основные действия в TUI:

- `Ctrl+R` - режим регистрации;
- `Ctrl+L` - режим входа;
- `Enter` - перейти к следующему полю или выполнить действие;
- `N` - создать новый секрет;
- `T` - выбрать text secret;
- `P` - выбрать login/password secret;
- `C` - выбрать bank card secret;
- `B` - выбрать binary secret;
- `O` - выбрать OTP secret;
- `U` - обновить выбранный секрет;
- `D` - удалить выбранный секрет;
- `S` - синхронизировать vault на экране списка;
- `R` - обновить список;
- `Q` - выйти из TUI.

Для OTP list показывает title, issuer/account и время до ротации. Detail показывает текущий код и progress до следующей ротации. OTP secret value не пишется в logs и не отображается в detail в открытом виде.

Пример запуска TUI с нестандартным адресом сервера:

```bash
GOPHKEEPER_SERVER_ADDRESS='localhost:9091' \
make tui
```

Пример запуска TUI с TLS:

```bash
GOPHKEEPER_SERVER_ADDRESS='localhost:9090' \
GOPHKEEPER_SERVER_TLS_ENABLED='true' \
GOPHKEEPER_SERVER_TLS_CERT_FILE='/path/to/server.crt' \
make tui
```

## CLI

Сейчас CLI умеет показывать версию, регистрировать пользователя, выполнять вход, создавать и обновлять секреты типов `text`, `login_password`, `bank_card` и `binary`, получать секрет по ID, выводить список активных секретов, мягко удалять секрет и запускать server-side sync. OTP доступен через TUI и client core.

Запуск через Go:

```bash
go run ./cmd/gophkeeper-cli version
```

Регистрация:

```bash
go run ./cmd/gophkeeper-cli register
```

Вход:

```bash
go run ./cmd/gophkeeper-cli login
```

Создание текстового секрета:

```bash
go run ./cmd/gophkeeper-cli create
```

Создание пары логин и пароль:

```bash
go run ./cmd/gophkeeper-cli create login-password
```

Создание банковской карты:

```bash
go run ./cmd/gophkeeper-cli create bank-card
```

Создание бинарного секрета из файла:

```bash
go run ./cmd/gophkeeper-cli create binary
```

Получение секрета:

```bash
go run ./cmd/gophkeeper-cli get
```

Список активных секретов:

```bash
go run ./cmd/gophkeeper-cli list
```

Обновление текстового секрета:

```bash
go run ./cmd/gophkeeper-cli update
```

Обновление пары логин и пароль:

```bash
go run ./cmd/gophkeeper-cli update login-password
```

Обновление банковской карты:

```bash
go run ./cmd/gophkeeper-cli update bank-card
```

Обновление бинарного секрета из файла:

```bash
go run ./cmd/gophkeeper-cli update binary
```

Мягкое удаление секрета любого типа:

```bash
go run ./cmd/gophkeeper-cli delete
```

Синхронизация изменений:

```bash
go run ./cmd/gophkeeper-cli sync
```

Команды `register`, `login`, `create`, `get`, `list`, `update`, `delete` и `sync` используют интерактивный ввод:

- login вводится обычным prompt;
- пароль входа вводится скрытым prompt;
- мастер-пароль вводится скрытым prompt;
- при регистрации мастер-пароль нужно повторить;
- пароль входа и мастер-пароль не должны совпадать;
- при регистрации CLI предупреждает, что мастер-пароль невозможно восстановить.

Команда `create` без указания типа создает текстовый секрет. Для остальных обязательных типов используются команды `create login-password`, `create bank-card` и `create binary`. Title сохраняется как encrypted metadata, а содержимое кодируется в одну из client payload schemas: `TextPayload`, `LoginPasswordPayload`, `BankCardPayload` или `BinaryPayload`. После кодирования metadata и payload шифруются на клиенте через vault key.

Команда `get` запрашивает ID секрета, получает encrypted item с сервера и расшифровывает metadata и payload на клиенте. В выводе всегда есть `ID`, `Type` и `Version`, чтобы пользователь мог сразу использовать актуальную версию для update/delete. Для `binary` команда дополнительно запрашивает `Output path` и записывает расшифрованный файл на диск с правами `0600`. Если файл по этому пути уже существует, CLI не перезаписывает его без явного выбора нового пути. Для открытия vault команды заново запрашивают login, пароль входа и мастер-пароль. Это нужно потому, что текущий CLI сохраняет только access token, но не хранит открытый vault key между запусками.

Команда `update` без указания типа обновляет текстовый секрет. Для остальных обязательных типов используются команды `update login-password`, `update bank-card` и `update binary`. Перед create/update CLI показывает подсказку по полям выбранного типа секрета. Команда `delete` не зависит от типа секрета: она удаляет любой item по `Secret ID` и `Expected version`. Команды `update` и `delete` требуют `Expected version`. Версию нужно брать из `list`, `get` или результата предыдущей команды. Если версия устарела, сервер возвращает version conflict.

Команда `sync` получает изменения с сервера, включая tombstones для удаленных записей. На текущем этапе offline cache еще нет, поэтому CLI не сохраняет sync cursor локально и отправляет пустой `changed_after`.

Перед запуском `register`, `login`, `create`, `get`, `list`, `update`, `delete` и `sync` должен быть запущен gRPC-сервер. По умолчанию клиент подключается к:

```text
localhost:9090
```

Переопределить адрес сервера можно так:

```bash
GOPHKEEPER_SERVER_ADDRESS='localhost:9091' \
go run ./cmd/gophkeeper-cli login
```

Access token сохраняется в локальный JSON-файл. По умолчанию используется:

```text
$HOME/.gophkeeper/token.json
```

Переопределить путь можно так:

```bash
GOPHKEEPER_TOKEN_FILE='/tmp/gophkeeper-token.json' \
go run ./cmd/gophkeeper-cli login
```

Файл token state создается с правами `0600`. В нем хранится access token и срок его действия. Мастер-пароль и открытый vault key туда не записываются.

Сборка CLI:

```bash
make build-cli
```

Проверка версии собранного бинарного файла:

```bash
./bin/gophkeeper-cli version
```

Команды CLI:

```text
gophkeeper version
gophkeeper register
gophkeeper login
gophkeeper create
gophkeeper create login-password
gophkeeper create bank-card
gophkeeper create binary
gophkeeper get
gophkeeper list
gophkeeper update
gophkeeper update login-password
gophkeeper update bank-card
gophkeeper update binary
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

Локальная сборка CLI для текущей платформы:

```bash
make build-cli
```

Кроссплатформенная сборка CLI:

```bash
make build-cli-all
```

Она собирает бинарные файлы в `bin`:

```text
gophkeeper-cli_linux_amd64
gophkeeper-cli_linux_arm64
gophkeeper-cli_darwin_amd64
gophkeeper-cli_darwin_arm64
gophkeeper-cli_windows_amd64.exe
```

Версию, дату сборки и commit hash можно переопределить через переменные:

```bash
VERSION=0.1.0 make build-cli-all
```

## Proto и gRPC code generation

Proto-контракты находятся в:

```text
api/proto/gophkeeper/v1/gophkeeper.proto
```

Swagger/OpenAPI файл находится в:

```text
api/openapi/gophkeeper.v1.swagger.json
```

Сгенерированный Go-код находится в:

```text
internal/gen/proto/gophkeeper/v1
```

Проверка EasyP-конфига:

```bash
easyp validate-config
```

Генерация Go-кода:

```bash
easyp generate
```

Генерация Swagger/OpenAPI:

```bash
make generate-openapi
```

OpenAPI генерируется из protobuf HTTP mappings `google.api.http`. Описаны методы `Register`, `Login`, `CreateItem`, `GetItem`, `ListItems`, `UpdateItem`, `DeleteItem`, `Sync`, тип `ITEM_TYPE_OTP` и основные ошибки `400`, `401`, `403`, `404`, `409`, `500`.

Сгенерированный код коммитится в репозиторий, чтобы проверяющему не нужно было обязательно устанавливать EasyP для обычной сборки проекта.

## Makefile команды

Основные команды проекта:

```bash
make proto
make test
make smoke
make tui
make build-cli
make build-tui
make build-cli-all
make coverage
make vet
```

Назначение команд:

- `make proto` - генерирует Go protobuf/gRPC код и Swagger/OpenAPI;
- `make test` - запускает `go test ./...`;
- `make smoke` - запускает smoke-тесты с живым PostgreSQL и gRPC-сервером;
- `make tui` - запускает TUI-клиент через `go run ./cmd/gophkeeper-tui`;
- `make build-cli` - собирает CLI для текущей платформы;
- `make build-tui` - собирает TUI для текущей платформы;
- `make build-cli-all` - собирает CLI под Linux, macOS и Windows;
- `make coverage` - проверяет порог покрытия;
- `make vet` - запускает `go vet ./...`.

## Тестирование

Запуск всех тестов:

```bash
go test ./...
```

Проверка покрытия с исключением generated protobuf code:

```bash
./scripts/check_coverage.sh
```

То же самое через Makefile:

```bash
make test
make coverage
make vet
```

Интеграционный smoke-сценарий с живым PostgreSQL и gRPC-сервером:

```bash
docker compose -f deploy/docker-compose.yml up -d
make smoke
```

`make smoke` запускает тесты с build tag `smoke`. Обычный `go test ./...` эти тесты не запускает, чтобы локальная быстрая проверка не требовала PostgreSQL.

В GitHub Actions этот же сценарий запускается отдельной job `postgres-smoke`. Эта job является CI-проверкой основных требований ТЗ: она поднимает PostgreSQL, стартует реальный gRPC-сервер внутри теста и проходит register, login, create, list, get, update, delete и sync для обязательных типов секретов.

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
- поведение CLI-команд через fake client core;
- поведение TUI model без интерактивного терминала;
- smoke flow для всех обязательных типов секретов: `text`, `login_password`, `bank_card`, `binary`, `otp`.

Generated protobuf code напрямую тестировать не планируется.

## Пошаговая приемочная проверка

Этот сценарий нужен, чтобы любой проверяющий мог локально пройти основные возможности проекта из ТЗ. Все команды выполняются из корня репозитория.

### 1. Проверить toolchain

Нужны:

- Go версии из `go.mod`;
- Docker;
- Docker Compose;
- `make`;
- свободный порт `5432` для PostgreSQL;
- свободный порт `9090` для gRPC-сервера.

Проверка:

```bash
go version
docker version
docker compose version
make --version
```

### 2. Запустить PostgreSQL

```bash
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml exec postgres pg_isready -U gophkeeper -d gophkeeper
```

Ожидаемый результат: `pg_isready` возвращает `accepting connections`.

### 3. Проверить тесты, vet и coverage

```bash
go test ./...
go vet ./...
./scripts/check_coverage.sh
make smoke
```

Ожидаемый результат:

- все тесты проходят;
- `go vet` завершается без ошибок;
- coverage не ниже 70%;
- generated protobuf code не учитывается в coverage threshold;
- smoke-сценарий проходит register, login, create/list/get/update/delete/sync для `text`, `login_password`, `bank_card`, `binary` и `otp` через реальный gRPC-сервер и PostgreSQL.

### 4. Собрать CLI

Сборка для текущей платформы:

```bash
make build-cli
./bin/gophkeeper-cli version
```

Ожидаемый результат: CLI печатает `Version`, `Build date` и `Commit`.

Кроссплатформенная сборка:

```bash
make build-cli-all
ls -1 bin
```

Ожидаемый результат: в `bin` появляются файлы:

```text
gophkeeper-cli
gophkeeper-cli_linux_amd64
gophkeeper-cli_linux_arm64
gophkeeper-cli_darwin_amd64
gophkeeper-cli_darwin_arm64
gophkeeper-cli_windows_amd64.exe
```

### 5. Запустить сервер

В отдельном терминале:

```bash
GOPHKEEPER_DATABASE_DSN='postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable' \
GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-access-token-secret-32-bytes' \
GOPHKEEPER_LOG_MODE='dev' \
go run ./cmd/gophkeeper-server
```

Ожидаемый результат: сервер применяет миграции и слушает `:9090`.

Альтернативный запуск через dev-скрипт:

```bash
./scripts/dev.sh server
```

### 6. Запустить TUI

В другом терминале:

```bash
make tui
```

Ожидаемый результат: открывается TUI-экран входа. Через `Ctrl+R` можно перейти к регистрации, ввести login, пароль входа, мастер-пароль и открыть vault. После регистрации или входа можно нажать `N`, затем `O`, создать OTP-секрет и увидеть текущий OTP-код в detail.

Сборка TUI:

```bash
make build-tui
./bin/gophkeeper-tui
```

### 7. Проверить CLI version

В другом терминале:

```bash
./bin/gophkeeper-cli version
```

Ожидаемый результат: команда завершается сразу и печатает версию. Это нормальное поведение CLI: процесс выполняет одну команду и завершается.

### 8. Зарегистрировать пользователя

```bash
./bin/gophkeeper-cli register
```

Пример вводимых данных:

```text
Login: user@example.com
Login password: login-password-123
Master password: master-password-123
Repeat master password: master-password-123
```

Ожидаемый результат:

```text
Регистрация выполнена
```

Проверяется:

- создание пользователя;
- hash пароля входа на сервере;
- генерация vault key на клиенте;
- шифрование vault key мастер-паролем;
- сохранение encrypted vault key metadata;
- запрет совпадения пароля входа и мастер-пароля.

### 9. Проверить вход

```bash
./bin/gophkeeper-cli login
```

Использовать те же login, пароль входа и мастер-пароль.

Ожидаемый результат:

```text
Вход выполнен
```

Проверяется:

- проверка password hash;
- выпуск JWT access token;
- сохранение token state в `$HOME/.gophkeeper/token.json`;
- расшифровка vault key на клиенте.

### 10. Создать секреты основных CLI типов

Текстовый секрет:

```bash
./bin/gophkeeper-cli create
```

Пример вводимых данных:

```text
Login: user@example.com
Login password: login-password-123
Master password: master-password-123
Title: first note
Secret text: very secret text
```

Ожидаемый результат:

```text
Секрет создан: <text-secret-id>
```

Сохранить `<text-secret-id>` для следующих шагов.

Пара логин и пароль:

```bash
./bin/gophkeeper-cli create login-password
```

Пример вводимых данных:

```text
Login: user@example.com
Login password: login-password-123
Master password: master-password-123
Title: GitHub account
Secret login: octocat
Secret password: github-secret-password
URL: https://github.com
Notes: work account
```

Сохранить `<login-password-secret-id>`.

Банковская карта:

```bash
./bin/gophkeeper-cli create bank-card
```

Пример вводимых данных:

```text
Login: user@example.com
Login password: login-password-123
Master password: master-password-123
Title: salary card
Card number: 4111111111111111
Cardholder name: IVAN IVANOV
Expiration month: 05
Expiration year: 2030
CVV: 123
Notes: main bank card
```

Сохранить `<bank-card-secret-id>`.

Бинарный секрет:

```bash
printf 'binary secret content' > /tmp/gophkeeper-binary-secret.txt
./bin/gophkeeper-cli create binary
```

Пример вводимых данных:

```text
Login: user@example.com
Login password: login-password-123
Master password: master-password-123
Title: private file
File path: /tmp/gophkeeper-binary-secret.txt
Content type: text/plain
```

Сохранить `<binary-secret-id>`.

Проверяется:

- protected gRPC method;
- client-side encryption metadata и payload;
- payload schemas `TextPayload`, `LoginPasswordPayload`, `BankCardPayload` и `BinaryPayload`;
- inline binary metadata, checksum и size limit;
- сохранение encrypted item на сервере.

### 11. Получить секреты по ID

```bash
./bin/gophkeeper-cli get
```

Ввести `<text-secret-id>` из предыдущего шага.

Ожидаемый результат:

```text
Title: first note
Type: text
Secret text: very secret text
```

Для `<login-password-secret-id>` ожидаемый результат содержит:

```text
Title: GitHub account
Type: login_password
Login: octocat
Password: github-secret-password
URL: https://github.com
Notes: work account
```

Для `<bank-card-secret-id>` ожидаемый результат содержит:

```text
Title: salary card
Type: bank_card
Card number: 4111111111111111
Cardholder name: IVAN IVANOV
Expiration: 05/2030
CVV: 123
Notes: main bank card
```

Для `<binary-secret-id>` команда дополнительно спросит `Output path`:

```text
Output path: /tmp/gophkeeper-restored-binary-secret.txt
```

Ожидаемый результат содержит:

```text
ID: <binary-secret-id>
Type: binary
Version: 1
Title: private file
File name: gophkeeper-binary-secret.txt
Content type: text/plain
Size bytes: <size>
Checksum SHA256: <checksum>
Written to: /tmp/gophkeeper-restored-binary-secret.txt
```

Проверить восстановленный файл:

```bash
cat /tmp/gophkeeper-restored-binary-secret.txt
```

Проверяется:

- проверка owner на сервере;
- получение encrypted item;
- расшифровка metadata и payload на клиенте.

### 12. Проверить список активных секретов

```bash
./bin/gophkeeper-cli list
```

Ожидаемый результат:

```text
+----------------------------+---------+----------------+----------------+
| ID                         | VERSION | TYPE           | TITLE          |
+----------------------------+---------+----------------+----------------+
| <text-secret-id>           | 1       | text           | first note     |
| <login-password-secret-id> | 1       | login_password | GitHub account |
| <bank-card-secret-id>      | 1       | bank_card      | salary card    |
| <binary-secret-id>         | 1       | binary         | private file   |
+----------------------------+---------+----------------+----------------+
```

Сохранить актуальную `version` текстового секрета. Она нужна для optimistic locking в следующих шагах.

Проверяется:

- list protected method;
- фильтрация deleted items;
- отображение ID, версии и title.

### 13. Обновить секреты основных CLI типов

Текстовый секрет:

```bash
./bin/gophkeeper-cli update
```

Пример вводимых данных:

```text
Secret ID: <text-secret-id>
Expected version: 1
Title: updated note
Secret text: updated secret text
```

Ожидаемый результат:

```text
Секрет обновлен: <text-secret-id>, version: 2
```

Проверяется:

- update protected method;
- expected version;
- version increment;
- повторное шифрование metadata и payload;
- понятная ошибка при version conflict.

Пара логин и пароль:

```bash
./bin/gophkeeper-cli update login-password
```

Пример вводимых данных:

```text
Secret ID: <login-password-secret-id>
Expected version: 1
Title: GitHub account updated
Secret login: octocat
Secret password: updated-github-secret-password
URL: https://github.com
Notes: updated work account
```

Ожидаемый результат:

```text
Секрет обновлен: <login-password-secret-id>, version: 2
```

Банковская карта:

```bash
./bin/gophkeeper-cli update bank-card
```

Пример вводимых данных:

```text
Secret ID: <bank-card-secret-id>
Expected version: 1
Title: salary card updated
Card number: 5555555555554444
Cardholder name: IVAN IVANOV
Expiration month: 06
Expiration year: 2031
CVV: 321
Notes: updated bank card
```

Ожидаемый результат:

```text
Секрет обновлен: <bank-card-secret-id>, version: 2
```

Бинарный секрет:

```bash
printf 'updated binary secret content' > /tmp/gophkeeper-binary-secret-updated.txt
./bin/gophkeeper-cli update binary
```

Пример вводимых данных:

```text
Secret ID: <binary-secret-id>
Expected version: 1
Title: private file updated
File path: /tmp/gophkeeper-binary-secret-updated.txt
Content type: text/plain
```

Ожидаемый результат:

```text
Секрет обновлен: <binary-secret-id>, version: 2
```

### 14. Проверить обновленные значения

```bash
./bin/gophkeeper-cli get
```

Ввести `<text-secret-id>`.

Ожидаемый результат:

```text
Title: updated note
Type: text
Secret text: updated secret text
```

Повторить `get` для `<login-password-secret-id>`, `<bank-card-secret-id>` и `<binary-secret-id>`. Для binary указать новый output path и проверить содержимое файла:

```text
Output path: /tmp/gophkeeper-restored-binary-secret-updated.txt
```

```bash
cat /tmp/gophkeeper-restored-binary-secret-updated.txt
```

### 15. Удалить секреты основных CLI типов

```bash
./bin/gophkeeper-cli delete
```

Пример вводимых данных:

```text
Secret ID: <text-secret-id>
Expected version: 2
```

Ожидаемый результат:

```text
Секрет удален: <text-secret-id>, version: 3
```

Повторить ту же команду для `<login-password-secret-id>`, `<bank-card-secret-id>` и `<binary-secret-id>`, используя актуальную версию `2`.

Проверяется:

- soft delete;
- expected version;
- deleted_at на сервере;
- deleted item не показывается как активный.

### 16. Проверить, что удаленный секрет не виден в active list

```bash
./bin/gophkeeper-cli list
```

Ожидаемый результат: удаленные `<text-secret-id>`, `<login-password-secret-id>`, `<bank-card-secret-id>` и `<binary-secret-id>` отсутствуют в списке активных секретов.

### 17. Проверить sync и tombstones

```bash
./bin/gophkeeper-cli sync
```

Ожидаемый результат: в выводе есть изменения пользователя, включая tombstones для всех четырех удаленных items со статусом `удален`.

Проверяется:

- server-side sync;
- changed items;
- tombstones;
- фильтрация по текущему пользователю;
- расшифровка synced payload на клиенте.

### 18. Проверить ошибку version conflict

Создать новый секрет:

```bash
./bin/gophkeeper-cli create
./bin/gophkeeper-cli list
```

Обновить его с актуальной версией, например `1`, затем повторить update с той же старой версией `1`.

Ожидаемый результат второго update: CLI возвращает ошибку с контекстом `version conflict`.

### 19. Проверить ошибку неверного мастер-пароля

```bash
./bin/gophkeeper-cli get
```

Ввести правильные login и пароль входа, но неверный мастер-пароль.

Ожидаемый результат: команда завершается ошибкой расшифровки vault key. Это корректно: мастер-пароль не хранится и не восстанавливается.

### 20. Остановить локальную инфраструктуру

Остановить сервер через `Ctrl+C`.

Остановить PostgreSQL без удаления данных:

```bash
docker compose -f deploy/docker-compose.yml stop
```

Удалить контейнеры:

```bash
docker compose -f deploy/docker-compose.yml down
```

Полностью очистить локальные данные PostgreSQL:

```bash
docker compose -f deploy/docker-compose.yml down -v
```

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
