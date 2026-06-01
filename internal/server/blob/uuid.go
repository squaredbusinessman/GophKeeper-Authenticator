package blob

import "github.com/google/uuid"

// IDGeneratorFunc адаптирует функцию генерации id к интерфейсу IDGenerator
type IDGeneratorFunc func() (string, error)

// NewID возвращает новый id
func (f IDGeneratorFunc) NewID() (string, error) {
	return f()
}

// NewUUID создает UUID для blob metadata
func NewUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return id.String(), nil
}
