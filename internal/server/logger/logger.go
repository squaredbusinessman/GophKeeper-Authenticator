// Package logger создает структурный логгер серверного приложения
package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New создает логгер серверного приложения для выбранного режима
func New(mode string) (*zap.Logger, error) {
	var cfg zap.Config

	switch mode {
	case "dev":
		cfg = zap.NewDevelopmentConfig()
		cfg.Encoding = "console"
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	case "prod":
		cfg = zap.NewProductionConfig()
	default:
		return nil, fmt.Errorf("unsupported log mode: %s", mode)
	}

	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.MessageKey = "message"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	log, err := cfg.Build()
	if err != nil {
		return nil, err
	}

	return log.With(zap.String("service", "gophkeeper-server")), nil
}
