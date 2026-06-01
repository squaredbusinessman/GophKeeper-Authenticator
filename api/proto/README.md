# api/proto

Здесь хранятся `.proto`-контракты gRPC API.

`.proto` является основным описанием gRPC API.

Swagger/OpenAPI генерируется из HTTP mappings protobuf и лежит в `api/openapi/gophkeeper.v1.swagger.json`.

Генерация protobuf Go-кода и Swagger/OpenAPI:

```bash
make proto
```

Runtime transport проекта остается gRPC. Swagger/OpenAPI описывает HTTP projection контракта.
