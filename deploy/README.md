# deploy

Здесь будут храниться файлы локального развертывания проекта.

Для MVP основной сценарий приемки - запуск сервера, PostgreSQL и MinIO через Docker Compose.

Запуск локального окружения:

```bash
docker compose -f deploy/docker-compose.yml up -d
```

PostgreSQL доступен на `localhost:5432`.

MinIO API доступен на `localhost:9000`.

MinIO Console доступна на `http://localhost:9001`.

Логин и пароль по умолчанию:

```text
gophkeeper
gophkeeper-minio-password
```

Bucket для encrypted blobs создается автоматически:

```text
gophkeeper-blobs
```
