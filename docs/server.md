# Сервер

Сервер предоставляет auth и vault API по gRPC. Vault-данные сохраняются в PostgreSQL как encrypted metadata и encrypted payload.

## Консистентность vault

Vault items используют optimistic versioning:

- `create` создает новую запись на сервере;
- `update` требует expected version от клиента;
- `delete` выполняет soft delete и также требует expected version;
- параллельные конфликтующие изменения возвращают version conflict вместо тихой перезаписи данных.

## Синхронизация

`sync` возвращает items, измененные после cursor timestamp, включая tombstones для удаленных записей.
