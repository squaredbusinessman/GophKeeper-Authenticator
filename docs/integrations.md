# Read the Docs и Codecov

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

Пример шага:

```yaml
- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v5
  with:
    token: ${{ secrets.CODECOV_TOKEN }}
    files: ./coverage.out
    fail_ci_if_error: true
```
