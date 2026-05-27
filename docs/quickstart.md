# Быстрый старт

Ниже полный локальный запуск на одном устройстве.

## 1. Подготовить env

```bash
cp deploy/.env.example deploy/.env
```

## 2. Запустить PostgreSQL и MinIO

```bash
docker compose -f deploy/docker-compose.yml up -d
```

Проверить контейнеры:

```bash
docker compose -f deploy/docker-compose.yml ps
```

## 3. Запустить сервер

```bash
set -a
source deploy/.env
set +a
go run ./cmd/gophkeeper-server
```

## 4. Запустить TUI

В новом терминале:

```bash
make tui
```

## 5. Проверить CLI

```bash
go run ./cmd/gophkeeper-cli version
go run ./cmd/gophkeeper-cli register
go run ./cmd/gophkeeper-cli create
go run ./cmd/gophkeeper-cli list
```

## 6. Проверить binary flow

```bash
printf 'binary secret content' > /tmp/gophkeeper-secret.txt
go run ./cmd/gophkeeper-cli create binary
```

Ввести:

```text
File path: /tmp/gophkeeper-secret.txt
Content type: text/plain
```

Файл будет зашифрован на клиенте и сохранен в MinIO как encrypted chunks.
