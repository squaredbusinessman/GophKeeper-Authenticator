# GophKeeper Authenticator

GophKeeper Authenticator - клиент-серверный менеджер секретов на Go. Клиенты шифруют metadata и payload локально до отправки данных на сервер, поэтому сервер хранит только зашифрованные данные vault.

## Возможности

- Регистрация и вход с отдельным мастер-паролем.
- Зашифрованные vault items для текста, логина и пароля, банковских карт, binary-файлов и OTP.
- Проверка expected version при обновлении и удалении секретов.
- gRPC API и сгенерированное OpenAPI-описание.
- CLI и TUI клиенты.

## Локальные проверки качества

```bash
make fmt-check
make lint
make test
make coverage
make security
make docs-build
```

## Внешние сервисы

- Документация Read the Docs: <https://gophkeeper-authenticator.readthedocs.io/>
- Покрытие Codecov: <https://app.codecov.io/gh/squaredbusinessman/GophKeeper-Authenticator>
