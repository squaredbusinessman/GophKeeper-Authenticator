// Package config загружает и проверяет конфигурацию серверного приложения
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

const minAccessTokenSecretLength = 32

// Config описывает настройки серверного приложения
type Config struct {
	GRPCAddress        string        `env:"GOPHKEEPER_GRPC_ADDRESS" env-default:":9090"`
	GRPCTLSEnabled     bool          `env:"GOPHKEEPER_GRPC_TLS_ENABLED" env-default:"false"`
	GRPCTLSCertFile    string        `env:"GOPHKEEPER_GRPC_TLS_CERT_FILE"`
	GRPCTLSKeyFile     string        `env:"GOPHKEEPER_GRPC_TLS_KEY_FILE"`
	DatabaseDSN        string        `env:"GOPHKEEPER_DATABASE_DSN" env-required:"true"`
	AccessTokenSecret  string        `env:"GOPHKEEPER_ACCESS_TOKEN_SECRET" env-required:"true"`
	AccessTokenTTL     time.Duration `env:"GOPHKEEPER_ACCESS_TOKEN_TTL" env-default:"5m"`
	BlobStorageEnabled bool          `env:"GOPHKEEPER_BLOB_STORAGE_ENABLED" env-default:"false"`
	MinIOEndpoint      string        `env:"GOPHKEEPER_MINIO_ENDPOINT"`
	MinIOAccessKey     string        `env:"GOPHKEEPER_MINIO_ACCESS_KEY"`
	MinIOSecretKey     string        `env:"GOPHKEEPER_MINIO_SECRET_KEY"`
	MinIOBucket        string        `env:"GOPHKEEPER_MINIO_BUCKET" env-default:"gophkeeper-blobs"`
	MinIOUseSSL        bool          `env:"GOPHKEEPER_MINIO_USE_SSL" env-default:"false"`
	BlobUploadTTL      time.Duration `env:"GOPHKEEPER_BLOB_UPLOAD_TTL" env-default:"24h"`
	BlobChunkSize      int64         `env:"GOPHKEEPER_BLOB_CHUNK_SIZE" env-default:"4194304"`
	BlobMaxSize        int64         `env:"GOPHKEEPER_BLOB_MAX_SIZE" env-default:"1073741824"`
	MigrationsEnabled  bool          `env:"GOPHKEEPER_MIGRATIONS_ENABLED" env-default:"true"`
	MigrationsDir      string        `env:"GOPHKEEPER_MIGRATIONS_DIR" env-default:"migrations"`
	DatabasePingTTL    time.Duration `env:"GOPHKEEPER_DATABASE_PING_TTL" env-default:"5s"`
	LogMode            string        `env:"GOPHKEEPER_LOG_MODE" env-default:"dev"`
}

// Load загружает конфигурацию серверного приложения из переменных окружения
func Load() (*Config, error) {
	cfg := &Config{}

	if err := cleanenv.ReadEnv(cfg); err != nil {
		return &Config{}, fmt.Errorf("read server config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return &Config{}, fmt.Errorf("validate server config: %w", err)
	}

	return cfg, nil
}

// Validate проверяет корректность конфигурации серверного приложения
func (c *Config) Validate() error {
	if strings.TrimSpace(c.GRPCAddress) == "" {
		return fmt.Errorf("grpc address is required")
	}

	if c.AccessTokenTTL <= 0 {
		return fmt.Errorf("access token ttl must be greater than zero")
	}

	if len(strings.TrimSpace(c.AccessTokenSecret)) < minAccessTokenSecretLength {
		return fmt.Errorf("access token secret must be at least %d characters", minAccessTokenSecretLength)
	}

	if c.BlobStorageEnabled {
		if strings.TrimSpace(c.MinIOEndpoint) == "" {
			return fmt.Errorf("minio endpoint is required when blob storage is enabled")
		}

		if strings.TrimSpace(c.MinIOAccessKey) == "" {
			return fmt.Errorf("minio access key is required when blob storage is enabled")
		}

		if strings.TrimSpace(c.MinIOSecretKey) == "" {
			return fmt.Errorf("minio secret key is required when blob storage is enabled")
		}

		if strings.TrimSpace(c.MinIOBucket) == "" {
			return fmt.Errorf("minio bucket is required when blob storage is enabled")
		}

		if c.BlobUploadTTL <= 0 {
			return fmt.Errorf("blob upload ttl must be greater than zero")
		}

		if c.BlobChunkSize <= 0 {
			return fmt.Errorf("blob chunk size must be greater than zero")
		}

		if c.BlobMaxSize <= 0 {
			return fmt.Errorf("blob max size must be greater than zero")
		}

		if c.BlobMaxSize < c.BlobChunkSize {
			return fmt.Errorf("blob max size must be greater than or equal to blob chunk size")
		}
	}

	if c.GRPCTLSEnabled {
		if strings.TrimSpace(c.GRPCTLSCertFile) == "" {
			return fmt.Errorf("grpc TLS cert file is required when tls is enabled")
		}

		if strings.TrimSpace(c.GRPCTLSKeyFile) == "" {
			return fmt.Errorf("grpc TLS key file is required when tls is enabled")
		}
	}

	if c.DatabasePingTTL <= 0 {
		return fmt.Errorf("database ping ttl must be greater than zero")
	}

	if c.MigrationsEnabled && strings.TrimSpace(c.MigrationsDir) == "" {
		return fmt.Errorf("migrations dir is required when migrations are enabled")
	}

	switch c.LogMode {
	case "dev", "prod":
	default:
		return fmt.Errorf("log mode must be dev or prod")
	}

	return nil
}
