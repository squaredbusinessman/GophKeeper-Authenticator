package config

import (
	"strings"
	"testing"
	"time"
)

const testAccessTokenSecret = "test-access-token-secret-32-bytes"

func TestLoadReturnsServerConfigWithDefaults(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://user:pass@localhost:5432/gophkeeper?sslmode=disable")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.GRPCAddress != ":9090" {
		t.Fatalf("GRPCAddress = %q, want %q", cfg.GRPCAddress, ":9090")
	}

	if cfg.GRPCTLSEnabled {
		t.Fatalf("GRPCTLSEnabled = true, want false")
	}

	if cfg.AccessTokenTTL != 5*time.Minute {
		t.Fatalf("AccessTokenTTL = %s, want %s", cfg.AccessTokenTTL, 15*time.Minute)
	}

	if cfg.DatabaseDSN == "" {
		t.Fatalf("DatabaseDSN is empty")
	}

	if cfg.AccessTokenSecret == "" {
		t.Fatalf("AccessTokenSecret is empty")
	}

	if cfg.LogMode != "dev" {
		t.Fatalf("LogMode = %q, want %q", cfg.LogMode, "dev")
	}
}

func TestLoadReturnsServerConfigFromEnv(t *testing.T) {
	t.Setenv("GOPHKEEPER_GRPC_ADDRESS", ":8080")
	t.Setenv("GOPHKEEPER_GRPC_TLS_ENABLED", "true")
	t.Setenv("GOPHKEEPER_GRPC_TLS_CERT_FILE", "/tmp/server.crt")
	t.Setenv("GOPHKEEPER_GRPC_TLS_KEY_FILE", "/tmp/server.key")
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_TTL", "30m")
	t.Setenv("GOPHKEEPER_BLOB_STORAGE_ENABLED", "true")
	t.Setenv("GOPHKEEPER_MINIO_ENDPOINT", "localhost:9000")
	t.Setenv("GOPHKEEPER_MINIO_ACCESS_KEY", "gophkeeper")
	t.Setenv("GOPHKEEPER_MINIO_SECRET_KEY", "gophkeeper-minio-password")
	t.Setenv("GOPHKEEPER_MINIO_BUCKET", "gophkeeper-blobs")
	t.Setenv("GOPHKEEPER_BLOB_UPLOAD_TTL", "12h")
	t.Setenv("GOPHKEEPER_BLOB_CHUNK_SIZE", "8388608")
	t.Setenv("GOPHKEEPER_BLOB_MAX_SIZE", "2147483648")
	t.Setenv("GOPHKEEPER_LOG_MODE", "prod")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.GRPCAddress != ":8080" {
		t.Fatalf("GRPCAddress = %q, want %q", cfg.GRPCAddress, ":8080")
	}

	if !cfg.GRPCTLSEnabled {
		t.Fatalf("GRPCTLSEnabled = false, want true")
	}

	if cfg.GRPCTLSCertFile != "/tmp/server.crt" {
		t.Fatalf("GRPCTLSCertFile = %q, want %q", cfg.GRPCTLSCertFile, "/tmp/server.crt")
	}

	if cfg.GRPCTLSKeyFile != "/tmp/server.key" {
		t.Fatalf("GRPCTLSKeyFile = %q, want %q", cfg.GRPCTLSKeyFile, "/tmp/server.key")
	}

	if cfg.DatabaseDSN != "postgres://custom" {
		t.Fatalf("DatabaseDSN = %q, want %q", cfg.DatabaseDSN, "postgres://custom")
	}

	if cfg.AccessTokenSecret != testAccessTokenSecret {
		t.Fatalf("AccessTokenSecret = %q, want %q", cfg.AccessTokenSecret, testAccessTokenSecret)
	}

	if cfg.AccessTokenTTL != 30*time.Minute {
		t.Fatalf("AccessTokenTTL = %s, want %s", cfg.AccessTokenTTL, 30*time.Minute)
	}

	if !cfg.BlobStorageEnabled {
		t.Fatalf("BlobStorageEnabled = false, want true")
	}

	if cfg.MinIOEndpoint != "localhost:9000" {
		t.Fatalf("MinIOEndpoint = %q, want localhost:9000", cfg.MinIOEndpoint)
	}

	if cfg.BlobUploadTTL != 12*time.Hour {
		t.Fatalf("BlobUploadTTL = %s, want %s", cfg.BlobUploadTTL, 12*time.Hour)
	}

	if cfg.BlobChunkSize != 8388608 {
		t.Fatalf("BlobChunkSize = %d, want 8388608", cfg.BlobChunkSize)
	}

	if cfg.BlobMaxSize != 2147483648 {
		t.Fatalf("BlobMaxSize = %d, want 2147483648", cfg.BlobMaxSize)
	}

	if cfg.LogMode != "prod" {
		t.Fatalf("LogMode = %q, want %q", cfg.LogMode, "prod")
	}
}

func TestLoadReturnsErrorWhenDatabaseDSNMissing(t *testing.T) {
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "DatabaseDSN") {
		t.Fatalf("Load() error = %q, want mention DatabaseDSN", err.Error())
	}
}

func TestLoadReturnsErrorWhenAccessTokenSecretMissing(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "AccessTokenSecret") {
		t.Fatalf("Load() error = %q, want mention AccessTokenSecret", err.Error())
	}
}

func TestLoadReturnsErrorWhenAccessTokenSecretTooShort(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", "short-secret")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("Load() error = %q, want mention minimum length", err.Error())
	}
}

func TestLoadReturnsErrorWhenTLSCertFileMissing(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)
	t.Setenv("GOPHKEEPER_GRPC_TLS_ENABLED", "true")
	t.Setenv("GOPHKEEPER_GRPC_TLS_KEY_FILE", "/tmp/server.key")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "cert file") {
		t.Fatalf("Load() error = %q, want mention cert file", err.Error())
	}
}

func TestLoadReturnsErrorWhenTLSKeyFileMissing(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)
	t.Setenv("GOPHKEEPER_GRPC_TLS_ENABLED", "true")
	t.Setenv("GOPHKEEPER_GRPC_TLS_CERT_FILE", "/tmp/server.crt")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "key file") {
		t.Fatalf("Load() error = %q, want mention key file", err.Error())
	}
}

func TestLoadReturnsErrorWhenBoolInvalid(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)
	t.Setenv("GOPHKEEPER_GRPC_TLS_ENABLED", "not-bool")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "GOPHKEEPER_GRPC_TLS_ENABLED") {
		t.Fatalf("Load() error = %q, want mention GOPHKEEPER_GRPC_TLS_ENABLED", err.Error())
	}
}

func TestLoadReturnsErrorWhenDurationInvalid(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_TTL", "not-duration")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "GOPHKEEPER_ACCESS_TOKEN_TTL") {
		t.Fatalf("Load() error = %q, want mention GOPHKEEPER_ACCESS_TOKEN_TTL", err.Error())
	}
}

func TestLoadReturnsErrorWhenLogModeInvalid(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)
	t.Setenv("GOPHKEEPER_LOG_MODE", "pretty")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "log mode") {
		t.Fatalf("Load() error = %q, want mention log mode", err.Error())
	}
}

func TestLoadReturnsErrorWhenBlobStorageEnabledWithoutMinIOEndpoint(t *testing.T) {
	t.Setenv("GOPHKEEPER_DATABASE_DSN", "postgres://custom")
	t.Setenv("GOPHKEEPER_ACCESS_TOKEN_SECRET", testAccessTokenSecret)
	t.Setenv("GOPHKEEPER_BLOB_STORAGE_ENABLED", "true")
	t.Setenv("GOPHKEEPER_MINIO_ACCESS_KEY", "gophkeeper")
	t.Setenv("GOPHKEEPER_MINIO_SECRET_KEY", "gophkeeper-minio-password")

	_, err := Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "minio endpoint") {
		t.Fatalf("Load() error = %q, want mention minio endpoint", err.Error())
	}
}

func TestValidateReturnsErrorWhenBlobMaxSizeBelowChunkSize(t *testing.T) {
	cfg := Config{
		GRPCAddress:        ":9090",
		DatabaseDSN:        "postgres://custom",
		AccessTokenSecret:  testAccessTokenSecret,
		AccessTokenTTL:     5 * time.Minute,
		BlobStorageEnabled: true,
		MinIOEndpoint:      "localhost:9000",
		MinIOAccessKey:     "gophkeeper",
		MinIOSecretKey:     "gophkeeper-minio-password",
		MinIOBucket:        "gophkeeper-blobs",
		BlobUploadTTL:      24 * time.Hour,
		BlobChunkSize:      1024,
		BlobMaxSize:        512,
		LogMode:            "dev",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "blob max size") {
		t.Fatalf("Validate() error = %q, want mention blob max size", err.Error())
	}
}

func TestValidateReturnsErrorWhenGRPCAddressEmpty(t *testing.T) {
	cfg := Config{
		GRPCAddress:       " ",
		DatabaseDSN:       "postgres://custom",
		AccessTokenSecret: testAccessTokenSecret,
		AccessTokenTTL:    5 * time.Minute,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "grpc address") {
		t.Fatalf("Validate() error = %q, want mention grpc address", err.Error())
	}
}

func TestValidateReturnsErrorWhenAccessTokenTTLNotPositive(t *testing.T) {
	cfg := Config{
		GRPCAddress:       ":9090",
		DatabaseDSN:       "postgres://custom",
		AccessTokenSecret: testAccessTokenSecret,
		AccessTokenTTL:    0,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("Validate() error = %q, want mention ttl", err.Error())
	}
}
