VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
OUTPUT_DIR ?= bin
SMOKE_DATABASE_DSN ?= postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable
VERSION_PACKAGE := github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version
LDFLAGS := -s -w -X $(VERSION_PACKAGE).Version=$(VERSION) -X $(VERSION_PACKAGE).BuildDate=$(BUILD_DATE) -X $(VERSION_PACKAGE).Commit=$(COMMIT)

.PHONY: build-cli build-tui build-cli-all proto generate-openapi fmt fmt-check lint test vet coverage security docs-build ci smoke certs server tui

build-cli:
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUTPUT_DIR)/gophkeeper-cli ./cmd/gophkeeper-cli

build-tui:
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUTPUT_DIR)/gophkeeper-tui ./cmd/gophkeeper-tui

build-cli-all:
	VERSION="$(VERSION)" BUILD_DATE="$(BUILD_DATE)" COMMIT="$(COMMIT)" OUTPUT_DIR="$(OUTPUT_DIR)" ./scripts/build_cli.sh

proto:
	easyp generate
	bash ./scripts/generate_openapi.sh

generate-openapi:
	bash ./scripts/generate_openapi.sh

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './internal/gen/*')

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './internal/gen/*'))" || \
		(echo "Go files are not formatted. Run make fmt."; gofmt -l $$(find . -name '*.go' -not -path './internal/gen/*'); exit 1)

lint:
	golangci-lint run ./...

test:
	go test ./...

vet:
	go vet ./...

coverage:
	./scripts/check_coverage.sh

security:
	govulncheck ./...

docs-build:
	mkdocs build --strict

ci: fmt-check lint test coverage security docs-build build-cli build-tui

smoke:
	GOPHKEEPER_TEST_DATABASE_DSN="$(SMOKE_DATABASE_DSN)" go test -tags=smoke ./internal/smoke

certs:
	./scripts/generate_local_tls.sh

server: certs
	go run ./cmd/gophkeeper-server

tui: certs
	go run ./cmd/gophkeeper-tui
