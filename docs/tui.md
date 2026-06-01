# TUI

TUI находится в:

```text
cmd/gophkeeper-tui
```

Запуск:

```bash
make tui
```

или:

```bash
go run ./cmd/gophkeeper-tui
```

## Экраны

- Welcome screen с banner и списком команд.
- Login/Register screen.
- Vault list.
- Secret detail.
- Create secret form.
- Update secret form.
- Delete confirmation.
- Save binary form.
- Status and error bar.

## Горячие клавиши

- `Ctrl+R` - регистрация.
- `Ctrl+L` - вход.
- `Enter` - открыть, перейти к следующему полю или выполнить действие.
- `N` - создать secret.
- `T` - text.
- `P` - login/password.
- `C` - bank card.
- `B` - binary.
- `O` - OTP.
- `U` - обновить выбранный secret.
- `D` - удалить выбранный secret.
- `R` - обновить список.
- `S` - синхронизировать vault.
- `Q` - выйти на стартовый экран или закрыть приложение.

## OTP

List показывает:

- title;
- issuer/account;
- время до смены кода.

Detail показывает:

- текущий OTP-код;
- сколько секунд осталось до смены;
- progress до следующей ротации.

OTP secret не отображается в открытом виде.

## Binary

TUI использует общий client core binary flow:

- файл читается локально;
- encrypted chunks загружаются в MinIO через `BlobService`;
- vault item хранит encrypted metadata с `blob_id`;
- при сохранении файла TUI скачивает chunks, расшифровывает их и пишет файл на диск.
