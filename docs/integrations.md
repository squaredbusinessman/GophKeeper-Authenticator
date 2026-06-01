# Read the Docs, Codecov и CircleCI

## Read the Docs

Документация собирается MkDocs и публикуется через Read the Docs.

Основные файлы:

```text
mkdocs.yml
.readthedocs.yaml
docs/requirements.txt
docs/
```

`.readthedocs.yaml` явно задает:

- Ubuntu image;
- Python version;
- `mkdocs.yml` как конфигурацию сборки;
- `docs/requirements.txt` как список Python-зависимостей.

Локальная сборка:

```bash
make docs-build
```

или напрямую:

```bash
mkdocs build --strict
```

## Codecov

Coverage profile создает скрипт:

```bash
./scripts/check_coverage.sh
```

Он создает:

```text
coverage.out
```

Для загрузки в Codecov в GitHub Actions используется `codecov/codecov-action`.

В GitHub repository secrets нужно добавить:

```text
CODECOV_TOKEN
```

Шаг загрузки coverage:

```yaml
- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v5
  with:
    token: ${{ secrets.CODECOV_TOKEN }}
    files: ./coverage.out
    flags: go
    name: go-unit-coverage
    fail_ci_if_error: true
```

### Recommended Codecov settings

Файл `codecov.yml` задает:

- общий project target `70%`;
- patch target `60%`;
- отдельные project statuses для client и server paths;
- GitHub annotations;
- PR comment layout с diff, flags и files.

В UI Codecov нужно включить настройки, которые Codecov рекомендует после первого upload:

1. Открыть `app.codecov.io`.
2. Перейти в проект `squaredbusinessman/GophKeeper-Authenticator`.
3. Открыть `Configuration`.
4. Включить `Project coverage checks`.
5. Включить `Project coverage reporting on Pull Request comment`.

После merge конфигурации в default branch Codecov будет:

- ставить coverage checks в PR;
- комментировать PR с изменением покрытия;
- показывать покрытие по флагам `go` и `circleci-go`;
- применять project и patch thresholds из `codecov.yml`.

## CircleCI

CircleCI pipeline описан в:

```text
.circleci/config.yml
```

Pipeline содержит jobs:

- `format` - проверка `gofmt`;
- `lint` - `golangci-lint`;
- `test` - unit tests, coverage gate и upload в Codecov;
- `security` - `govulncheck`;
- `build` - сборка CLI/TUI artifacts;
- `docs` - сборка MkDocs.

В CircleCI project environment variables нужно добавить:

```text
CODECOV_TOKEN
```

Codecov CircleCI Orb автоматически использует переменную `CODECOV_TOKEN`.

CircleCI upload помечен флагом:

```text
circleci-go
```
