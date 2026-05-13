// Package handler содержит gRPC-обработчики серверного API
package handler

import gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"

// AuthHandler обрабатывает запросы сервиса аутентификации
type AuthHandler struct {
	gophkeeperv1.UnimplementedAuthServiceServer
}

// NewAuthHandler создает обработчик сервиса аутентификации
func NewAuthHandler() *AuthHandler {
	return &AuthHandler{}
}
