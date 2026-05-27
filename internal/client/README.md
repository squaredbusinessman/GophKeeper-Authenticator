# internal/client

Клиентская часть приложения.

Здесь находится общий client core, который должен быть отделен от CLI, TUI и будущего GUI.

## Граница client core

`internal/client/core` содержит бизнес-логику клиентской авторизации и открытия vault.

Core не должен:

- читать stdin;
- печатать в stdout/stderr;
- знать про команды CLI;
- показывать prompts;
- принимать решения о тексте ошибок для пользователя;
- хранить UI-состояние.

UI-слой передает в core уже готовые значения: login, login password и master password. Core возвращает результат или ошибку, а CLI/TUI/GUI уже решают, как это показать пользователю.

## Auth flow

Регистрация:

1. UI получает `login`, `loginPassword`, `masterPassword`.
2. `core.AuthService.Register` генерирует новый `vault key`.
3. `vault key` шифруется через `internal/client/crypto/vaultkey` мастер-паролем.
4. На сервер отправляется `RegisterRequest` с login password и encrypted vault key metadata.
5. Core ожидает от сервера `access_token` и срок действия token.
6. Token сохраняется через `TokenStore`.
7. В вызывающий слой возвращается `Session` с access token и открытым vault key.

Вход:

1. UI получает `login`, `loginPassword`, `masterPassword`.
2. `core.AuthService.Login` отправляет login password на сервер.
3. Сервер возвращает `access_token` и encrypted vault key metadata.
4. Core расшифровывает vault key мастер-паролем.
5. Если мастер-пароль неверный, token не сохраняется.
6. Если vault key открыт успешно, token сохраняется через `TokenStore`.
7. В вызывающий слой возвращается `Session`.

Login password и master password разделены намеренно:

- login password нужен серверу для проверки личности пользователя;
- master password остается на клиенте и нужен только для открытия vault key;
- сервер не должен получать master password или открытый vault key.

## Token state

`TokenStore` это абстракция сохранения access token:

```go
type TokenStore interface {
	Save(context.Context, TokenState) error
}
```

Так core не зависит от конкретного способа хранения. Сейчас есть файловая реализация `FileTokenStore`, которая пишет JSON-файл с правами `0600`.

Формат файла:

```json
{
  "access_token": "jwt-value",
  "expires_at": "2026-05-19T12:30:00Z"
}
```

Файловый store умеет:

- создавать директорию под token file;
- атомарно заменять файл через временный файл;
- сохранять token state в JSON-файл с приватными правами.

Путь к token file задается клиентским config через `GOPHKEEPER_TOKEN_FILE`. Если переменная не задана, используется путь по умолчанию:

```text
$HOME/.gophkeeper/token.json
```

## Проверка

Тесты клиентского core:

```bash
go test ./internal/client/core
```

Полная проверка проекта:

```bash
go test ./...
```
