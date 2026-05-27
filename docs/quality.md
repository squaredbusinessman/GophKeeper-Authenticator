# Проверки качества

Локальные проверки:

```bash
make fmt-check
make lint
make test
make vet
make coverage
make security
make docs-build
```

## Coverage

Coverage проверяется скриптом:

```bash
./scripts/check_coverage.sh
```

Скрипт:

- запускает `go test ./... -coverprofile`;
- исключает generated protobuf code;
- считает общий процент;
- падает, если покрытие ниже `70%`.

Порог можно переопределить:

```bash
COVERAGE_THRESHOLD=75 ./scripts/check_coverage.sh
```

## Smoke test

Smoke flow запускается с живым PostgreSQL:

```bash
make smoke
```

Переменная DSN:

```env
GOPHKEEPER_TEST_DATABASE_DSN=postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable
```

Smoke test проверяет:

- регистрацию;
- вход;
- CRUD vault items;
- OTP payload;
- binary upload/download через BlobService;
- sync;
- TLS server startup.

## CI

GitHub Actions запускает:

- formatting check;
- `go vet`;
- tests with coverage;
- CLI build;
- TUI build;
- server build;
- PostgreSQL smoke flow.
