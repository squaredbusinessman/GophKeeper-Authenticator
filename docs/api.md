# API

API описан в Protocol Buffers в директории `api/proto/gophkeeper/v1`.

Сгенерированное OpenAPI-описание находится в `api/openapi/gophkeeper.v1.swagger.json`.

```bash
make proto
make generate-openapi
```

OpenAPI генерируется из protobuf HTTP mappings `google.api.http`.
