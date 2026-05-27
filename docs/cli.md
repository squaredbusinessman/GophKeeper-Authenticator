# CLI

CLI находится в:

```text
cmd/gophkeeper-cli
```

## Команды

Версия:

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

Создать text secret:

```bash
go run ./cmd/gophkeeper-cli create
```

Создать login/password secret:

```bash
go run ./cmd/gophkeeper-cli create login-password
```

Создать bank card secret:

```bash
go run ./cmd/gophkeeper-cli create bank-card
```

Создать binary secret:

```bash
go run ./cmd/gophkeeper-cli create binary
```

Получить secret по id:

```bash
go run ./cmd/gophkeeper-cli get
```

Список секретов:

```bash
go run ./cmd/gophkeeper-cli list
```

Обновить secret:

```bash
go run ./cmd/gophkeeper-cli update
go run ./cmd/gophkeeper-cli update login-password
go run ./cmd/gophkeeper-cli update bank-card
go run ./cmd/gophkeeper-cli update binary
```

Удалить secret:

```bash
go run ./cmd/gophkeeper-cli delete
```

Синхронизировать изменения:

```bash
go run ./cmd/gophkeeper-cli sync
```

## Binary

CLI binary-команды используют `BlobService`.

При создании или обновлении пользователь вводит:

- `Title` - название секрета;
- `File path` - путь к локальному файлу;
- `Content type` - MIME type файла.

При `get` для binary CLI запрашивает `Output directory`, скачивает encrypted chunks, расшифровывает файл и сохраняет его с исходным именем.

CLI не перезаписывает существующий файл в директории назначения.
