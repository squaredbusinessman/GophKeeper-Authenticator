#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_DIR="$(cd "$ROOT_DIR" && go list -m -f '{{.Dir}}' github.com/grpc-ecosystem/grpc-gateway/v2)"

cd "$ROOT_DIR"
mkdir -p api/openapi

protoc \
  -I . \
  -I api/proto \
  -I "$GATEWAY_DIR" \
  --openapiv2_out api/openapi \
  --openapiv2_opt logtostderr=true,allow_merge=true,merge_file_name=gophkeeper.v1,output_format=json \
  api/proto/gophkeeper/v1/gophkeeper.proto

if [ -f api/openapi/gophkeeper.swagger.json ]; then
  mv api/openapi/gophkeeper.swagger.json api/openapi/gophkeeper.v1.swagger.json
fi

go run ./scripts/patch_openapi_errors.go api/openapi/gophkeeper.v1.swagger.json
