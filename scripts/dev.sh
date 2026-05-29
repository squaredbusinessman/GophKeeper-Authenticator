#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/deploy/docker-compose.yml"

DB_USER="${POSTGRES_USER:-gophkeeper}"
DB_NAME="${POSTGRES_DB:-gophkeeper}"
DB_DSN="${GOPHKEEPER_DATABASE_DSN:-postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable}"
ACCESS_TOKEN_SECRET="${GOPHKEEPER_ACCESS_TOKEN_SECRET:-local-dev-access-token-secret-32-bytes}"
LOG_MODE="${GOPHKEEPER_LOG_MODE:-dev}"
GRPC_ADDRESS="${GOPHKEEPER_GRPC_ADDRESS:-:9090}"
CLIENT_SERVER_ADDRESS="${GOPHKEEPER_SERVER_ADDRESS:-localhost:9090}"
TLS_CERT_FILE="${GOPHKEEPER_GRPC_TLS_CERT_FILE:-${ROOT_DIR}/certs/server.crt}"
TLS_KEY_FILE="${GOPHKEEPER_GRPC_TLS_KEY_FILE:-${ROOT_DIR}/certs/server.key}"

print_usage() {
  cat <<USAGE
Usage:
  ./scripts/dev.sh db
  ./scripts/dev.sh server
  ./scripts/dev.sh cli <command>
  ./scripts/dev.sh sync
  ./scripts/dev.sh stop-db

Commands:
  db       Поднять PostgreSQL и дождаться готовности
  server   Поднять PostgreSQL и запустить gRPC-сервер
  cli      Запустить CLI-команду с локальным адресом сервера
  sync     Короткий alias для './scripts/dev.sh cli sync'
  stop-db  Остановить PostgreSQL без удаления данных
USAGE
}

start_db() {
  docker compose -f "${COMPOSE_FILE}" up -d

  for _ in {1..30}; do
    if docker compose -f "${COMPOSE_FILE}" exec -T postgres pg_isready -U "${DB_USER}" -d "${DB_NAME}" >/dev/null 2>&1; then
      echo "PostgreSQL is ready"
      return 0
    fi

    sleep 1
  done

  echo "PostgreSQL is not ready" >&2
  docker compose -f "${COMPOSE_FILE}" logs --tail=50 postgres >&2
  return 1
}

run_server() {
  start_db

  cd "${ROOT_DIR}"

  GOPHKEEPER_DATABASE_DSN="${DB_DSN}" \
  GOPHKEEPER_ACCESS_TOKEN_SECRET="${ACCESS_TOKEN_SECRET}" \
  GOPHKEEPER_LOG_MODE="${LOG_MODE}" \
  GOPHKEEPER_GRPC_ADDRESS="${GRPC_ADDRESS}" \
  GOPHKEEPER_GRPC_TLS_CERT_FILE="${TLS_CERT_FILE}" \
  GOPHKEEPER_GRPC_TLS_KEY_FILE="${TLS_KEY_FILE}" \
  go run ./cmd/gophkeeper-server
}

run_cli() {
  cd "${ROOT_DIR}"

  GOPHKEEPER_SERVER_ADDRESS="${CLIENT_SERVER_ADDRESS}" \
  GOPHKEEPER_SERVER_TLS_CERT_FILE="${TLS_CERT_FILE}" \
  go run ./cmd/gophkeeper-cli "$@"
}

stop_db() {
  docker compose -f "${COMPOSE_FILE}" stop
}

command="${1:-server}"
shift || true

case "${command}" in
  db)
    start_db
    ;;
  server)
    "${ROOT_DIR}/scripts/generate_local_tls.sh"
    run_server
    ;;
  cli)
    if [[ "$#" -eq 0 ]]; then
      echo "CLI command is required" >&2
      print_usage
      exit 1
    fi
    run_cli "$@"
    ;;
  sync)
    run_cli sync
    ;;
  stop-db)
    stop_db
    ;;
  -h|--help|help)
    print_usage
    ;;
  *)
    echo "Unknown command: ${command}" >&2
    print_usage
    exit 1
    ;;
esac
