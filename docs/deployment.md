# Развертывание

Проект рассчитан на локальную проверку на одном устройстве. Внешние managed-сервисы не нужны.

## Локальная инфраструктура

Сервисы описаны в `deploy/docker-compose.yml`:

- PostgreSQL;
- MinIO;
- `minio-init` для создания bucket.

Создать env-файл:

```bash
cp deploy/.env.example deploy/.env
```

Запустить инфраструктуру:

```bash
docker compose -f deploy/docker-compose.yml up -d
```

Проверить PostgreSQL:

```bash
docker compose -f deploy/docker-compose.yml exec postgres pg_isready -U gophkeeper -d gophkeeper
```

MinIO:

```text
API: localhost:9000
Console: http://localhost:9001
Login: gophkeeper
Password: gophkeeper-minio-password
Bucket: gophkeeper-blobs
```

## Запуск сервера

```bash
set -a
source deploy/.env
set +a
go run ./cmd/gophkeeper-server
```

По умолчанию сервер слушает:

```text
:9090
```

## Запуск клиентов

TUI:

```bash
make tui
```

CLI:

```bash
go run ./cmd/gophkeeper-cli version
go run ./cmd/gophkeeper-cli register
go run ./cmd/gophkeeper-cli create
```

## Остановка

Остановить контейнеры без удаления данных:

```bash
docker compose -f deploy/docker-compose.yml stop
```

Удалить контейнеры:

```bash
docker compose -f deploy/docker-compose.yml down
```

Удалить контейнеры и локальные данные PostgreSQL и MinIO:

```bash
docker compose -f deploy/docker-compose.yml down -v
```
