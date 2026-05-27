# OpenAPI

Основной transport проекта - gRPC. OpenAPI-файл используется как HTTP projection protobuf-контракта для выполнения требования Swagger-документации.

Файл:

```text
api/openapi/gophkeeper.v1.swagger.json
```

## Генерация

```bash
make generate-openapi
```

или вместе с protobuf Go-кодом:

```bash
make proto
```

## Что описано

- `Register`;
- `Login`;
- `CreateItem`;
- `GetItem`;
- `ListItems`;
- `UpdateItem`;
- `DeleteItem`;
- `Sync`;
- item type `OTP`;
- основные error responses.

## Swagger UI локально

Можно поднять Swagger UI через Docker:

```bash
docker run --rm -p 8080:8080 \
  -e SWAGGER_JSON=/spec/gophkeeper.v1.swagger.json \
  -v "$PWD/api/openapi:/spec" \
  swaggerapi/swagger-ui
```

После запуска открыть:

```text
http://localhost:8080
```
