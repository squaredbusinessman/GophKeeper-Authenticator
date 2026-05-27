# Синхронизация

Синхронизация реализована как online gRPC flow.

## Правила

- Сервер является источником истины.
- Каждый vault item имеет `version`.
- `update` и `delete` требуют `expected_version`.
- Удаление выполняется через `deleted_at`.
- Tombstones возвращаются через sync, чтобы другие клиенты увидели удаление.

## Sync command

CLI:

```bash
go run ./cmd/gophkeeper-cli sync
```

TUI:

```text
S
```

## Что возвращает Sync

`Sync` возвращает:

- измененные items;
- удаленные items как tombstones;
- `next_changed_after` cursor.

На текущем этапе offline cache не реализован, поэтому CLI не сохраняет cursor между запусками.

## Конфликты версий

Если клиент отправляет устаревший `expected_version`, сервер возвращает version conflict. Клиент показывает понятную ошибку пользователю.
