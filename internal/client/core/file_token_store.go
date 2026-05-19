package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// ErrTokenStateNotFound означает, что сохраненный access token еще не создан
	ErrTokenStateNotFound = errors.New("token state not found")
)

// FileTokenStore хранит состояние access token в локальном JSON-файле клиента
type FileTokenStore struct {
	path string
}

type tokenStateFile struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// NewFileTokenStore создает файловое хранилище token state
func NewFileTokenStore(path string) *FileTokenStore {
	return &FileTokenStore{path: path}
}

// Save сохраняет token state в файл с правами доступа только для текущего пользователя
func (s *FileTokenStore) Save(ctx context.Context, state TokenState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := state.validate(); err != nil {
		return err
	}

	path, err := s.validatePath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create token state dir: %w", err)
	}

	tempFile, err := os.CreateTemp(dir, ".token-*.tmp")
	if err != nil {
		return fmt.Errorf("create token state temp file: %w", err)
	}

	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	encoder := json.NewEncoder(tempFile)
	encoder.SetIndent("", "  ")

	if err = encoder.Encode(tokenStateFile{
		AccessToken: state.AccessToken,
		ExpiresAt:   state.ExpiresAt.UTC(),
	}); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("encode token state: %w", err)
	}

	if err = tempFile.Chmod(0o600); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("set token state file permissions: %w", err)
	}

	if err = tempFile.Close(); err != nil {
		return fmt.Errorf("close token state file: %w", err)
	}

	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace token state file: %w", err)
	}

	return nil
}

// Load загружает сохраненный token state из файла
func (s *FileTokenStore) Load(ctx context.Context) (TokenState, error) {
	if err := ctx.Err(); err != nil {
		return TokenState{}, err
	}

	path, err := s.validatePath()
	if err != nil {
		return TokenState{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return TokenState{}, ErrTokenStateNotFound
		}

		return TokenState{}, fmt.Errorf("read token state file: %w", err)
	}

	var payload tokenStateFile
	if err = json.Unmarshal(data, &payload); err != nil {
		return TokenState{}, fmt.Errorf("decode token state file: %w", err)
	}

	state := TokenState{
		AccessToken: payload.AccessToken,
		ExpiresAt:   payload.ExpiresAt,
	}
	if err = state.validate(); err != nil {
		return TokenState{}, fmt.Errorf("validate token state file: %w", err)
	}

	return state, nil
}

func (s *FileTokenStore) validatePath() (string, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return "", fmt.Errorf("token state file path is required")
	}

	return s.path, nil
}

func (s TokenState) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return fmt.Errorf("access token is required")
	}

	if s.ExpiresAt.IsZero() {
		return fmt.Errorf("access token expires at is required")
	}

	return nil
}
