VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
OUTPUT_DIR ?= bin
SMOKE_DATABASE_DSN ?= postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable
VERSION_PACKAGE := github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version
LDFLAGS := -s -w -X $(VERSION_PACKAGE).Version=$(VERSION) -X $(VERSION_PACKAGE).BuildDate=$(BUILD_DATE) -X $(VERSION_PACKAGE).Commit=$(COMMIT)

.PHONY: build-cli build-tui build-cli-all generate-openapi test vet coverage smoke

build-cli:
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUTPUT_DIR)/gophkeeper-cli ./cmd/gophkeeper-cli

build-tui:
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUTPUT_DIR)/gophkeeper-tui ./cmd/gophkeeper-tui

build-cli-all:
	VERSION="$(VERSION)" BUILD_DATE="$(BUILD_DATE)" COMMIT="$(COMMIT)" OUTPUT_DIR="$(OUTPUT_DIR)" ./scripts/build_cli.sh

generate-openapi:
	bash ./scripts/generate_openapi.sh

test:
	go test ./...

vet:
	go vet ./...

coverage:
	./scripts/check_coverage.sh

smoke:
	GOPHKEEPER_TEST_DATABASE_DSN="$(SMOKE_DATABASE_DSN)" go test -tags=smoke ./internal/smoke
