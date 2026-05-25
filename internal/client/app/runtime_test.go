package app

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/config"
)

func TestNewRuntimeBuildsSharedClientDependencies(t *testing.T) {
	runtime, err := NewRuntime(&config.Config{
		ServerAddress: "localhost:9090",
		TokenFile:     filepath.Join(t.TempDir(), "token.json"),
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()

	if runtime.Conn == nil {
		t.Fatalf("Conn = nil")
	}

	if runtime.AuthClient == nil {
		t.Fatalf("AuthClient = nil")
	}

	if runtime.VaultClient == nil {
		t.Fatalf("VaultClient = nil")
	}

	if runtime.TokenStore == nil {
		t.Fatalf("TokenStore = nil")
	}

	if runtime.AuthService == nil {
		t.Fatalf("AuthService = nil")
	}

	if runtime.VaultService == nil {
		t.Fatalf("VaultService = nil")
	}
}

func TestNewRuntimeReturnsTLSCredentialError(t *testing.T) {
	_, err := NewRuntime(&config.Config{
		ServerAddress:     "localhost:9090",
		ServerTLSEnabled:  true,
		ServerTLSCertFile: filepath.Join(t.TempDir(), "missing.crt"),
		TokenFile:         filepath.Join(t.TempDir(), "token.json"),
	})
	if err == nil {
		t.Fatalf("NewRuntime() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "load server TLS credentials") {
		t.Fatalf("NewRuntime() error = %q, want TLS credentials", err.Error())
	}
}

func TestLoadRuntimeLoadsConfigFromEnv(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token.json")
	t.Setenv("GOPHKEEPER_SERVER_ADDRESS", "localhost:9090")
	t.Setenv("GOPHKEEPER_SERVER_TLS_ENABLED", "false")
	t.Setenv("GOPHKEEPER_TOKEN_FILE", tokenFile)

	runtime, err := LoadRuntime()
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	defer runtime.Close()

	if runtime.Config.TokenFile != tokenFile {
		t.Fatalf("TokenFile = %q, want %q", runtime.Config.TokenFile, tokenFile)
	}
}

func TestLoadRuntimeWrapsConfigError(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_ADDRESS", " ")
	t.Setenv("GOPHKEEPER_TOKEN_FILE", filepath.Join(t.TempDir(), "token.json"))

	_, err := LoadRuntime()
	if err == nil {
		t.Fatalf("LoadRuntime() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "error loading config") {
		t.Fatalf("LoadRuntime() error = %q, want error loading config", err.Error())
	}
}

func TestRuntimeCloseAllowsNilReceiver(t *testing.T) {
	var runtime *Runtime
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewRuntimeRejectsNilConfig(t *testing.T) {
	_, err := NewRuntime(nil)
	if err == nil {
		t.Fatalf("NewRuntime() error = nil, want error")
	}
}

func TestNewRuntimeValidatesConfig(t *testing.T) {
	_, err := NewRuntime(&config.Config{
		ServerAddress: " ",
		TokenFile:     filepath.Join(t.TempDir(), "token.json"),
	})
	if err == nil {
		t.Fatalf("NewRuntime() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "validate client config") {
		t.Fatalf("NewRuntime() error = %q, want validate client config", err.Error())
	}
}

func TestLoadRuntimeUsesDefaultTokenFile(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_ADDRESS", "localhost:9090")
	t.Setenv("GOPHKEEPER_SERVER_TLS_ENABLED", "false")
	t.Setenv("GOPHKEEPER_TOKEN_FILE", "")

	runtime, err := LoadRuntime()
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	defer runtime.Close()

	if strings.TrimSpace(runtime.Config.TokenFile) == "" {
		t.Fatalf("TokenFile is empty")
	}

	if !strings.HasSuffix(runtime.Config.TokenFile, filepath.Join(".gophkeeper", "token.json")) {
		t.Fatalf("TokenFile = %q, want default token path", runtime.Config.TokenFile)
	}
}
