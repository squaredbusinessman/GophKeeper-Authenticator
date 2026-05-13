// Package logger создает структурный логгер серверного приложения
package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New создает базовый логгер серверного приложения
func New() (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.MessageKey = "message"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	log, err := cfg.Build()
	if err != nil {
		return nil, err
	}

	return log.With(zap.String("service", "gophkeeper-server")), nil
}
