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
- typed client payload schemas для `login_password`, `text`, `bank_card` и `binary`;
- inline binary metadata, checksum и size limit;
- coverage gate в CI с порогом не ниже 70%;
- кроссплатформенная сборка CLI под Linux, macOS и Windows.

Команды ниже описывают рабочий сценарий текущего состояния проекта.

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
- `internal/client` - клиентская бизнес-логика и client-side crypto;
- `internal/server` - серверная логика и инфраструктура;
- `internal/shared` - общие пакеты;
- `deploy` - локальная инфраструктура для разработки и проверки;
- `migrations` - SQL-миграции базы данных.

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

Это позволяет менять параметры в будущем и при этом проверять старые хеши с теми параметрами, с которыми они были созданы.

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

В MVP используется только access token. Refresh token flow остается расширением после надежного MVP.

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

`GOPHKEEPER_LOG_MODE` управляет форматом логов сервера:

- `dev` - цветной console output для локальной разработки;
- `prod` - JSON output для CI и production-like запуска.

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
GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-secret-change-me' \
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
GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-secret-change-me' \
GOPHKEEPER_LOG_MODE='dev' \
go run ./cmd/gophkeeper-server
```

Ожидаемый результат при старте в `dev` режиме - цветной console log от `zap` с полями `service`, `address` и `tls_enabled`.

Остановить сервер можно через `Ctrl+C`.

## CLI

Сейчас CLI умеет показывать версию, регистрировать пользователя, выполнять вход, создавать и обновлять секреты типов `text`, `login_password`, `bank_card` и `binary`, получать секрет по ID, выводить список активных секретов, мягко удалять секрет и запускать server-side sync.

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

Проверка покрытия с исключением generated protobuf code:

```bash
./scripts/check_coverage.sh
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
- поведение CLI-команд через fake client core.
- smoke flow для всех обязательных типов секретов: `text`, `login_password`, `bank_card`, `binary`.

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
- generated protobuf code не учитывается в coverage threshold.
- smoke-сценарий проходит register, login, create/list/get/update/delete для `text`, `login_password`, `bank_card` и `binary`, а также sync tombstones через реальный gRPC-сервер и PostgreSQL.

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
GOPHKEEPER_ACCESS_TOKEN_SECRET='local-dev-secret-change-me' \
GOPHKEEPER_LOG_MODE='dev' \
go run ./cmd/gophkeeper-server
```

Ожидаемый результат: сервер применяет миграции и слушает `:9090`.

Альтернативный запуск через dev-скрипт:

```bash
./scripts/dev.sh server
```

### 6. Проверить CLI version

В другом терминале:

```bash
./bin/gophkeeper-cli version
```

Ожидаемый результат: команда завершается сразу и печатает версию. Это нормальное поведение CLI: процесс выполняет одну команду и завершается.

### 7. Зарегистрировать пользователя

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

### 8. Проверить вход

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

### 9. Создать секреты всех обязательных типов

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

### 10. Получить секреты по ID

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

### 11. Проверить список активных секретов

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

### 12. Обновить секреты всех обязательных типов

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

### 13. Проверить обновленные значения

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

### 14. Удалить секреты всех обязательных типов

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

### 15. Проверить, что удаленный секрет не виден в active list

```bash
./bin/gophkeeper-cli list
```

Ожидаемый результат: удаленные `<text-secret-id>`, `<login-password-secret-id>`, `<bank-card-secret-id>` и `<binary-secret-id>` отсутствуют в списке активных секретов.

### 16. Проверить sync и tombstones

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

### 17. Проверить ошибку version conflict

Создать новый секрет:

```bash
./bin/gophkeeper-cli create
./bin/gophkeeper-cli list
```

Обновить его с актуальной версией, например `1`, затем повторить update с той же старой версией `1`.

Ожидаемый результат второго update: CLI возвращает ошибку с контекстом `version conflict`.

### 18. Проверить ошибку неверного мастер-пароля

```bash
./bin/gophkeeper-cli get
```

Ввести правильные login и пароль входа, но неверный мастер-пароль.

Ожидаемый результат: команда завершается ошибкой расшифровки vault key. Это корректно: мастер-пароль не хранится и не восстанавливается.

### 19. Остановить локальную инфраструктуру

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

Практическое следствие: пользовательские секреты не нужно передавать как аргументы командной строки.
