# Deployment

Local development services are defined under `deploy/`.

```bash
docker compose -f deploy/docker-compose.yml up -d
```

CI builds and stores package artifacts for the CLI and TUI clients. Documentation is built as a static site and stored as a CircleCI artifact.
