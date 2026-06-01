//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type document map[string]any

func main() {
	if len(os.Args) != 2 {
		exitf("usage: go run ./scripts/patch_openapi_errors.go <swagger.json>")
	}

	path := os.Args[1]
	raw, err := os.ReadFile(path)
	if err != nil {
		exitf("read swagger: %v", err)
	}

	var doc document
	if err = json.Unmarshal(raw, &doc); err != nil {
		exitf("decode swagger: %v", err)
	}

	addSecurityDefinition(doc)
	updateInfo(doc)
	addErrorDefinition(doc)
	addErrorResponses(doc)

	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		exitf("encode swagger: %v", err)
	}
	encoded = append(encoded, '\n')

	if err = os.WriteFile(path, encoded, 0o600); err != nil {
		exitf("write swagger: %v", err)
	}
}

func updateInfo(doc document) {
	info := objectAt(doc, "info")
	info["title"] = "GophKeeper gRPC HTTP projection"
	info["version"] = "v1"
	info["description"] = "Runtime transport remains gRPC. This Swagger file documents the HTTP projection of the protobuf contract"
}

func addSecurityDefinition(doc document) {
	defs := objectAt(doc, "securityDefinitions")
	defs["BearerAuth"] = map[string]any{
		"type":        "apiKey",
		"name":        "Authorization",
		"in":          "header",
		"description": "JWT access token in format Bearer <token>",
	}
}

func addErrorDefinition(doc document) {
	defs := objectAt(doc, "definitions")
	defs["gophkeeper.v1.ErrorResponse"] = map[string]any{
		"type":        "object",
		"description": "Ошибка HTTP projection для gRPC status",
		"properties": map[string]any{
			"code": map[string]any{
				"type":        "integer",
				"format":      "int32",
				"description": "HTTP status code",
			},
			"message": map[string]any{
				"type":        "string",
				"description": "User facing error message",
			},
			"grpcCode": map[string]any{
				"type":        "string",
				"description": "gRPC status code",
			},
		},
	}
}

func addErrorResponses(doc document) {
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		return
	}

	for _, pathKey := range sortedKeys(paths) {
		pathItem, ok := paths[pathKey].(map[string]any)
		if !ok {
			continue
		}

		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			operation, ok := pathItem[method].(map[string]any)
			if !ok {
				continue
			}

			if method != "post" || pathKey != "/v1/auth/register" && pathKey != "/v1/auth/login" {
				operation["security"] = []any{map[string]any{"BearerAuth": []any{}}}
			}

			responses := objectAt(operation, "responses")
			for code, description := range errorDescriptions() {
				if _, exists := responses[code]; exists {
					continue
				}
				responses[code] = map[string]any{
					"description": description,
					"schema": map[string]any{
						"$ref": "#/definitions/gophkeeper.v1.ErrorResponse",
					},
				}
			}
		}
	}
}

func errorDescriptions() map[string]string {
	return map[string]string{
		"400": "Invalid request",
		"401": "Unauthenticated",
		"403": "Permission denied",
		"404": "Resource not found",
		"409": "Version conflict",
		"500": "Internal server error",
	}
}

func objectAt(parent map[string]any, key string) map[string]any {
	value, ok := parent[key].(map[string]any)
	if ok {
		return value
	}

	value = map[string]any{}
	parent[key] = value
	return value
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func exitf(format string, args ...any) {
	var message bytes.Buffer
	_, _ = fmt.Fprintf(&message, format, args...)
	_, _ = fmt.Fprintln(os.Stderr, message.String())
	os.Exit(1)
}
