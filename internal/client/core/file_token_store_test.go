package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileTokenStoreSaveWritesTokenState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "token.json")
	store := NewFileTokenStore(path)
	expiresAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)

	err := store.Save(context.Background(), TokenState{
		AccessToken: "access-token",
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var state tokenStateFile
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if state.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want access-token", state.AccessToken)
	}

	if !state.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("ExpiresAt = %s, want %s", state.ExpiresAt, expiresAt)
	}
}

func TestFileTokenStoreSaveCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	store := NewFileTokenStore(path)

	err := store.Save(context.Background(), TokenState{
		AccessToken: "access-token",
		ExpiresAt:   time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestFileTokenStoreSaveReturnsErrorForInvalidState(t *testing.T) {
	store := NewFileTokenStore(filepath.Join(t.TempDir(), "token.json"))

	err := store.Save(context.Background(), TokenState{
		ExpiresAt: time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatalf("Save() error = nil, want error")
	}
}
