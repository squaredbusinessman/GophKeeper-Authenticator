package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReturnsClientConfigWithDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ServerAddress != "localhost:9090" {
		t.Fatalf("ServerAddress = %q, want %q", cfg.ServerAddress, "localhost:9090")
	}

	if cfg.ServerTLSEnabled {
		t.Fatalf("ServerTLSEnabled = true, want false")
	}

	if cfg.TokenFile == "" {
		t.Fatalf("TokenFile is empty")
	}
}

func TestLoadReturnsClientConfigFromEnv(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_ADDRESS", "127.0.0.1:9091")
	t.Setenv("GOPHKEEPER_SERVER_TLS_ENABLED", "true")
	t.Setenv("GOPHKEEPER_SERVER_TLS_CERT_FILE", "/tmp/server.crt")
	t.Setenv("GOPHKEEPER_TOKEN_FILE", "/tmp/token.json")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ServerAddress != "127.0.0.1:9091" {
		t.Fatalf("ServerAddress = %q, want %q", cfg.ServerAddress, "127.0.0.1:9091")
	}

	if !cfg.ServerTLSEnabled {
		t.Fatalf("ServerTLSEnabled = false, want true")
	}

	if cfg.ServerTLSCertFile != "/tmp/server.crt" {
		t.Fatalf("ServerTLSCertFile = %q, want %q", cfg.ServerTLSCertFile, "/tmp/server.crt")
	}

	if cfg.TokenFile != "/tmp/token.json" {
		t.Fatalf("TokenFile = %q, want %q", cfg.TokenFile, "/tmp/token.json")
	}
}

func TestLoadUsesDefaultTokenFileWhenEnvMissing(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("os.UserHomeDir() error = %v", err)
	}

	want := filepath.Join(homeDir, ".gophkeeper", "token.json")
	if cfg.TokenFile != want {
		t.Fatalf("TokenFile = %q, want %q", cfg.TokenFile, want)
	}
}

func TestLoadReturnsErrorWhenBoolInvalid(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_TLS_ENABLED", "not-bool")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "GOPHKEEPER_SERVER_TLS_ENABLED") {
		t.Fatalf("Load() error = %q, want mention GOPHKEEPER_SERVER_TLS_ENABLED", err.Error())
	}
}

func TestLoadReturnsErrorWhenTLSCertFileMissing(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_TLS_ENABLED", "true")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "cert file") {
		t.Fatalf("Load() error = %q, want mention cert file", err.Error())
	}
}

func TestValidateReturnsErrorWhenServerAddressEmpty(t *testing.T) {
	cfg := Config{
		ServerAddress: " ",
		TokenFile:     "/tmp/token.json",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "server address") {
		t.Fatalf("Validate() error = %q, want mention server address", err.Error())
	}
}

func TestValidateReturnsErrorWhenTokenFileEmpty(t *testing.T) {
	cfg := Config{
		ServerAddress: "localhost:9090",
		TokenFile:     " ",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "token file") {
		t.Fatalf("Validate() error = %q, want mention token file", err.Error())
	}
}

func TestValidateReturnsErrorWhenTLSCertFileMissing(t *testing.T) {
	cfg := Config{
		ServerAddress:    "localhost:9090",
		ServerTLSEnabled: true,
		TokenFile:        "/tmp/token.json",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "cert file") {
		t.Fatalf("Validate() error = %q, want mention cert file", err.Error())
	}
}
