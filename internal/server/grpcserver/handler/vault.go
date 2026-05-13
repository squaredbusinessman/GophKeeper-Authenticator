package handler

import gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"

// VaultHandler обрабатывает запросы сервиса хранилища
type VaultHandler struct {
	gophkeeperv1.UnimplementedVaultServiceServer
}

// NewVaultHandler создает обработчик сервиса хранилища
func NewVaultHandler() *VaultHandler {
	return &VaultHandler{}
}
