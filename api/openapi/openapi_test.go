package openapi

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSwaggerContainsRequiredContract(t *testing.T) {
	raw, err := os.ReadFile("gophkeeper.v1.swagger.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	paths := objectValue(t, doc, "paths")
	for _, tt := range []struct {
		path   string
		method string
	}{
		{path: "/v1/auth/register", method: "post"},
		{path: "/v1/auth/login", method: "post"},
		{path: "/v1/vault/items", method: "post"},
		{path: "/v1/vault/items/{id}", method: "get"},
		{path: "/v1/vault/items", method: "get"},
		{path: "/v1/vault/items/{id}", method: "put"},
		{path: "/v1/vault/items/{id}", method: "delete"},
		{path: "/v1/vault/sync", method: "post"},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			pathItem := objectValue(t, paths, tt.path)
			operation := objectValue(t, pathItem, tt.method)
			responses := objectValue(t, operation, "responses")

			for _, code := range []string{"400", "401", "403", "404", "409", "500"} {
				if _, ok := responses[code]; !ok {
					t.Fatalf("response %s is missing", code)
				}
			}
		})
	}

	definitions := objectValue(t, doc, "definitions")
	itemType := objectValue(t, definitions, "v1ItemType")
	enumValues, ok := itemType["enum"].([]any)
	if !ok {
		t.Fatalf("v1ItemType enum is missing")
	}

	if !contains(enumValues, "ITEM_TYPE_OTP") {
		t.Fatalf("ITEM_TYPE_OTP is missing")
	}
}

func objectValue(t *testing.T, values map[string]any, key string) map[string]any {
	t.Helper()

	value, ok := values[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is missing", key)
	}

	return value
}

func contains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}
