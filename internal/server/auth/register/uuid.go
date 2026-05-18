package register

import (
	"crypto/rand"
	"fmt"
)

// NewUUID генерирует UUID v4 для серверных сущностей
func NewUUID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", fmt.Errorf("generate UUID bytes: %w", err)
	}

	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:]), nil
}
