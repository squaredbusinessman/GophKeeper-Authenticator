// Package config загружает и проверяет конфигурацию серверного приложения
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config описывает настройки серверного приложения
type Config struct {
	GRPCAddress       string        `env:"GOPHKEEPER_GRPC_ADDRESS" env-default:":9090"`
	GRPCTLSEnabled    bool          `env:"GOPHKEEPER_GRPC_TLS_ENABLED" env-default:"false"`
	GRPCTLSCertFile   string        `env:"GOPHKEEPER_GRPC_TLS_CERT_FILE"`
	GRPCTLSKeyFile    string        `env:"GOPHKEEPER_GRPC_TLS_KEY_FILE"`
	DatabaseDSN       string        `env:"GOPHKEEPER_DATABASE_DSN" env-required:"true"`
	AccessTokenSecret string        `env:"GOPHKEEPER_ACCESS_TOKEN_SECRET" env-required:"true"`
	AccessTokenTTL    time.Duration `env:"GOPHKEEPER_ACCESS_TOKEN_TTL" env-default:"5m"`
	MigrationsEnabled bool          `env:"GOPHKEEPER_MIGRATIONS_ENABLED" env-default:"true"`
	MigrationsDir     string        `env:"GOPHKEEPER_MIGRATIONS_DIR" env-default:"migrations"`
	DatabasePingTTL   time.Duration `env:"GOPHKEEPER_DATABASE_PING_TTL" env-default:"5s"`
	LogMode           string        `env:"GOPHKEEPER_LOG_MODE" env-default:"dev"`
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
