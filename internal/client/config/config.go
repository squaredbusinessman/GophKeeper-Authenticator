// Package config загружает и проверяет конфигурацию клиента
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ilyakaznacheev/cleanenv"
)

var (
	// ErrServerAddressRequired означает пустой адрес сервера клиента
	ErrServerAddressRequired = errors.New("server address is required")
	// ErrTokenFileRequired означает пустой путь к файлу токена
	ErrTokenFileRequired = errors.New("token file is required")
	// ErrServerTLSCertFileRequired означает пустой путь к TLS-сертификату сервера
	ErrServerTLSCertFileRequired = errors.New("server TLS cert file is required")
)

// Config описывает настройки клиента
type Config struct {
	ServerAddress     string `env:"GOPHKEEPER_SERVER_ADDRESS" env-default:"localhost:9090"`
	ServerTLSCertFile string `env:"GOPHKEEPER_SERVER_TLS_CERT_FILE" env-default:"certs/server.crt"`
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
		return ErrServerAddressRequired
	}

	if strings.TrimSpace(c.TokenFile) == "" {
		return ErrTokenFileRequired
	}

	if strings.TrimSpace(c.ServerTLSCertFile) == "" {
		return ErrServerTLSCertFileRequired
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
