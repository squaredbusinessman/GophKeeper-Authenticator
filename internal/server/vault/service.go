package vault

import (
	"context"
	"fmt"
	"strings"
)

// Repository сохраняет и загружает encrypted vault items
type Repository interface {
	CreateItem(context.Context, CreateItemParams) (Item, error)
	FindItemByID(context.Context, string) (Item, error)
}

// IDGenerator генерирует ID vault item
type IDGenerator interface {
	NewID() (string, error)
}

// IDGeneratorFunc адаптер функции генерации ID к интерфейсу IDGenerator
type IDGeneratorFunc func() (string, error)

// NewID вызывает функцию генерации ID
func (f IDGeneratorFunc) NewID() (string, error) {
	return f()
}

// Service выполняет use case создания и получения vault items
type Service struct {
	repository  Repository
	idGenerator IDGenerator
}

// NewService создает vault service
func NewService(repository Repository, idGenerator IDGenerator) *Service {
	if idGenerator == nil {
		idGenerator = IDGeneratorFunc(NewUUID)
	}

	return &Service{
		repository:  repository,
		idGenerator: idGenerator,
	}
}

// CreateItem создает encrypted vault item для пользователя
func (s *Service) CreateItem(ctx context.Context, input CreateItemInput) (Item, error) {
	if err := input.Validate(); err != nil {
		return Item{}, err
	}

	itemID, err := s.idGenerator.NewID()
	if err != nil {
		return Item{}, fmt.Errorf("generate item id: %w", err)
	}

	item, err := s.repository.CreateItem(ctx, CreateItemParams{
		ItemID:               itemID,
		UserID:               strings.TrimSpace(input.UserID),
		Type:                 input.Type,
		Metadata:             input.Metadata,
		Payload:              input.Payload,
		EncryptionAlg:        strings.TrimSpace(input.EncryptionAlg),
		PayloadSchemaVersion: input.PayloadSchemaVersion,
	})
	if err != nil {
		return Item{}, fmt.Errorf("create vault item: %w", err)
	}

	return item, nil
}

// GetItem возвращает encrypted vault item и проверяет владельца
func (s *Service) GetItem(ctx context.Context, input GetItemInput) (Item, error) {
	if err := input.Validate(); err != nil {
		return Item{}, err
	}

	item, err := s.repository.FindItemByID(ctx, strings.TrimSpace(input.ItemID))
	if err != nil {
		return Item{}, fmt.Errorf("find vault item by id: %w", err)
	}

	if item.UserID != strings.TrimSpace(input.UserID) {
		return Item{}, ErrAccessDenied
	}

	return item, nil
}
