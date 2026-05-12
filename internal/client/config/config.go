// Package config загружает и проверяет конфигурацию клиента
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config описывает настройки клиента
type Config struct {
	ServerAddress     string `env:"GOPHKEEPER_SERVER_ADDRESS" env-default:"localhost:9090"`
	ServerTLSEnabled  bool   `env:"GOPHKEEPER_SERVER_TLS_ENABLED" env-default:"false"`
	ServerTLSCertFile string `env:"GOPHKEEPER_SERVER_TLS_CERT_FILE"`
	TokenFile         string `env:"GOPHKEEPER_TOKEN_FILE"`
}

// Load загружает конфигурацию клиента из переменных окружения
func Load() (*Config, error) {
	cfg := &Config{}

	if err := cleanenv.ReadEnv(cfg); err != nil {
		return cfg, fmt.Errorf("read client config: %w", err)
	}

	if strings.TrimSpace(cfg.TokenFile) == "" {
		cfg.TokenFile = defaultTokenFile()
	}

	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("validate client config: %w", err)
	}

	return cfg, nil
}

// Validate проверяет корректность конфигурации клиента
func (c *Config) Validate() error {
	if strings.TrimSpace(c.ServerAddress) == "" {
		return fmt.Errorf("server address is required")
	}

	if strings.TrimSpace(c.TokenFile) == "" {
		return fmt.Errorf("token file is required")
	}

	if c.ServerTLSEnabled && strings.TrimSpace(c.ServerTLSCertFile) == "" {
		return fmt.Errorf("server TLS cert file is required when tls is enabled")
	}

	return nil
}

func defaultTokenFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".gophkeeper", "token.json")
	}

	return filepath.Join(homeDir, ".gophkeeper", "token.json")
}
