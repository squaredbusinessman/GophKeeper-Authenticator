package vault

import (
	"crypto/rand"
	"fmt"

	"github.com/google/uuid"
)

// NewUUID генерирует UUID для vault item
func NewUUID() (string, error) {
	uuidBytes := make([]byte, 16)
	if _, err := rand.Read(uuidBytes); err != nil {
		return "", fmt.Errorf("generate UUID bytes: %w", err)
	}

	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80

	return uuid.UUID(uuidBytes).String(), nil
}
