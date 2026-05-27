# Общий клиентский слой

CLI и TUI не содержат прямой gRPC и crypto-логики. Оба клиента создают общий runtime из пакета `internal/client/app` и используют client core из `internal/client/core`.

## Состав runtime

Runtime собирает:

- gRPC connection;
- auth client;
- vault client;
- blob client;
- token store;
- auth service;
- vault service;
- blob service.

Клиентские настройки читаются из переменных окружения:

```env
GOPHKEEPER_SERVER_ADDRESS=localhost:9090
GOPHKEEPER_SERVER_TLS_ENABLED=false
GOPHKEEPER_SERVER_TLS_CERT_FILE=
GOPHKEEPER_TOKEN_FILE=$HOME/.gophkeeper/token.json
```

## Vault session

Для работы с vault клиенту нужны:

- access token для gRPC metadata;
- vault key для расшифрования пользовательских данных.

Access token может сохраняться в файл token store. Vault key не сохраняется как открытый ключ между запусками CLI. Поэтому CLI заново запрашивает login password и master password для команд работы с vault.

TUI держит session в памяти процесса до выхода пользователя из приложения.

## Payload schemas

Client core кодирует plaintext в типизированные JSON-схемы:

- `TextPayload`;
- `LoginPasswordPayload`;
- `BankCardPayload`;
- `BinaryPayload`;
- `OTPPayload`.

После кодирования payload шифруется через AES-256-GCM. Сервер видит только encrypted bytes и номер версии схемы.

## Binary flow

Для binary client core использует `BlobService`:

1. Читает файл локально.
2. Считает plaintext checksum.
3. Режет файл на chunks.
4. Шифрует каждый chunk через vault key.
5. Загружает encrypted chunks через gRPC streaming.
6. Сохраняет в vault item только encrypted metadata с `blob_id`.

Эта логика общая для CLI и TUI.
