// Package shutdown помогает корректно завершать серверное приложение
package shutdown

import (
	"context"
	"os/signal"
	"syscall"
)

// Context возвращает context, который завершается при SIGINT или SIGTERM
func Context(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
}
