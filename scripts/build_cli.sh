#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/bin}"
VERSION="${VERSION:-dev}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
PACKAGE="github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version"

LDFLAGS="-s -w"
LDFLAGS="${LDFLAGS} -X ${PACKAGE}.Version=${VERSION}"
LDFLAGS="${LDFLAGS} -X ${PACKAGE}.BuildDate=${BUILD_DATE}"
LDFLAGS="${LDFLAGS} -X ${PACKAGE}.Commit=${COMMIT}"

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

mkdir -p "${OUTPUT_DIR}"

for target in "${TARGETS[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  output="${OUTPUT_DIR}/gophkeeper-cli_${goos}_${goarch}"

  if [[ "${goos}" == "windows" ]]; then
    output="${output}.exe"
  fi

  echo "Building ${output}"
  (
    cd "${ROOT_DIR}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" go build \
      -trimpath \
      -ldflags "${LDFLAGS}" \
      -o "${output}" \
      ./cmd/gophkeeper-cli
  )
done
