package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileTokenStoreSaveAndLoad(t *testing.T) {
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

	state, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
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

func TestFileTokenStoreLoadReturnsNotFoundForMissingFile(t *testing.T) {
	store := NewFileTokenStore(filepath.Join(t.TempDir(), "missing.json"))

	_, err := store.Load(context.Background())
	if !errors.Is(err, ErrTokenStateNotFound) {
		t.Fatalf("Load() error = %v, want ErrTokenStateNotFound", err)
	}
}

func TestFileTokenStoreLoadReturnsErrorForBrokenJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(path, []byte("{broken json"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	store := NewFileTokenStore(path)

	_, err := store.Load(context.Background())
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
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
