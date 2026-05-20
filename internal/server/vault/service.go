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
	ListItems(context.Context, ListItemsParams) ([]Item, error)
	UpdateItem(context.Context, UpdateItemParams) (Item, error)
	DeleteItem(context.Context, DeleteItemParams) (DeleteItemResult, error)
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

// Service выполняет use case работы с vault items
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

// ListItems возвращает encrypted vault items пользователя
func (s *Service) ListItems(ctx context.Context, input ListItemsInput) ([]Item, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	items, err := s.repository.ListItems(ctx, ListItemsParams{
		UserID:         strings.TrimSpace(input.UserID),
		IncludeDeleted: input.IncludeDeleted,
	})
	if err != nil {
		return nil, fmt.Errorf("list vault items: %w", err)
	}

	return items, nil
}

// UpdateItem обновляет encrypted vault item с проверкой владельца и expected version
func (s *Service) UpdateItem(ctx context.Context, input UpdateItemInput) (Item, error) {
	if err := input.Validate(); err != nil {
		return Item{}, err
	}

	userID := strings.TrimSpace(input.UserID)
	itemID := strings.TrimSpace(input.ItemID)

	item, err := s.repository.FindItemByID(ctx, itemID)
	if err != nil {
		return Item{}, fmt.Errorf("find vault item by id: %w", err)
	}

	if item.UserID != userID {
		return Item{}, ErrAccessDenied
	}

	if item.Version != input.ExpectedVersion {
		return Item{}, ErrVersionConflict
	}

	updatedItem, err := s.repository.UpdateItem(ctx, UpdateItemParams{
		ItemID:               itemID,
		UserID:               userID,
		ExpectedVersion:      input.ExpectedVersion,
		Type:                 input.Type,
		Metadata:             input.Metadata,
		Payload:              input.Payload,
		EncryptionAlg:        strings.TrimSpace(input.EncryptionAlg),
		PayloadSchemaVersion: input.PayloadSchemaVersion,
	})
	if err != nil {
		return Item{}, fmt.Errorf("update vault item: %w", err)
	}

	return updatedItem, nil
}

// DeleteItem мягко удаляет vault item с проверкой владельца и expected version
func (s *Service) DeleteItem(ctx context.Context, input DeleteItemInput) (DeleteItemResult, error) {
	if err := input.Validate(); err != nil {
		return DeleteItemResult{}, err
	}

	userID := strings.TrimSpace(input.UserID)
	itemID := strings.TrimSpace(input.ItemID)

	item, err := s.repository.FindItemByID(ctx, itemID)
	if err != nil {
		return DeleteItemResult{}, fmt.Errorf("find vault item by id: %w", err)
	}

	if item.UserID != userID {
		return DeleteItemResult{}, ErrAccessDenied
	}

	if item.Version != input.ExpectedVersion {
		return DeleteItemResult{}, ErrVersionConflict
	}

	result, err := s.repository.DeleteItem(ctx, DeleteItemParams{
		ItemID:          itemID,
		UserID:          userID,
		ExpectedVersion: input.ExpectedVersion,
	})
	if err != nil {
		return DeleteItemResult{}, fmt.Errorf("delete vault item: %w", err)
	}

	return result, nil
}
