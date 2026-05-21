// Package vault содержит серверные use case для encrypted vault items
package vault

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrInvalidInput означает некорректные входные данные vault use case
	ErrInvalidInput = errors.New("invalid vault input")

	// ErrItemNotFound означает, что item не найден
	ErrItemNotFound = errors.New("vault item not found")

	// ErrAccessDenied означает попытку доступа к item другого пользователя
	ErrAccessDenied = errors.New("vault item access denied")

	// ErrVersionConflict означает, что item изменился после версии, известной клиенту
	ErrVersionConflict = errors.New("vault item version conflict")
)

// ItemType описывает тип encrypted vault item на сервере
type ItemType string

const (
	// ItemTypeLoginPassword хранит encrypted login/password item
	ItemTypeLoginPassword ItemType = "login_password"

	// ItemTypeText хранит encrypted text item
	ItemTypeText ItemType = "text"

	// ItemTypeBinary хранит encrypted binary item
	ItemTypeBinary ItemType = "binary"

	// ItemTypeBankCard хранит encrypted bank card item
	ItemTypeBankCard ItemType = "bank_card"
)

// EncryptedData содержит ciphertext и nonce для encrypted metadata или payload
type EncryptedData struct {
	Ciphertext []byte
	Nonce      []byte
}

// Item описывает encrypted vault item с техническими полями версии и удаления
type Item struct {
	ID                   string
	UserID               string
	Type                 ItemType
	Metadata             EncryptedData
	Payload              EncryptedData
	EncryptionAlg        string
	PayloadSchemaVersion uint32
	Version              int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DeletedAt            *time.Time
}

// CreateItemInput содержит данные use case создания encrypted vault item
type CreateItemInput struct {
	UserID               string
	Type                 ItemType
	Metadata             EncryptedData
	Payload              EncryptedData
	EncryptionAlg        string
	PayloadSchemaVersion uint32
}

// GetItemInput содержит данные use case получения encrypted vault item
type GetItemInput struct {
	UserID string
	ItemID string
}

// CreateItemParams содержит данные repository для сохранения encrypted vault item
type CreateItemParams struct {
	ItemID               string
	UserID               string
	Type                 ItemType
	Metadata             EncryptedData
	Payload              EncryptedData
	EncryptionAlg        string
	PayloadSchemaVersion uint32
}

// ListItemsInput содержит данные use case получения списка encrypted vault items
type ListItemsInput struct {
	UserID         string
	IncludeDeleted bool
}

// UpdateItemInput содержит данные use case обновления encrypted vault item
type UpdateItemInput struct {
	UserID               string
	ItemID               string
	ExpectedVersion      int64
	Type                 ItemType
	Metadata             EncryptedData
	Payload              EncryptedData
	EncryptionAlg        string
	PayloadSchemaVersion uint32
}

// DeleteItemInput содержит данные use case soft delete encrypted vault item
type DeleteItemInput struct {
	UserID          string
	ItemID          string
	ExpectedVersion int64
}

// ListItemsParams содержит данные repository для получения списка encrypted vault items
type ListItemsParams struct {
	UserID         string
	IncludeDeleted bool
}

// UpdateItemParams содержит данные repository для обновления encrypted vault item
type UpdateItemParams struct {
	ItemID               string
	UserID               string
	ExpectedVersion      int64
	Type                 ItemType
	Metadata             EncryptedData
	Payload              EncryptedData
	EncryptionAlg        string
	PayloadSchemaVersion uint32
}

// DeleteItemParams содержит данные repository для soft delete encrypted vault item
type DeleteItemParams struct {
	ItemID          string
	UserID          string
	ExpectedVersion int64
}

// DeleteItemResult содержит результат soft delete encrypted vault item
type DeleteItemResult struct {
	ItemID    string
	Version   int64
	DeletedAt time.Time
}

// SyncItemsInput содержит данные use case синхронизации encrypted vault items
type SyncItemsInput struct {
	UserID       string
	ChangedAfter time.Time
}

// SyncItemsParams содержит данные repository для выборки измененных encrypted vault items
type SyncItemsParams struct {
	UserID       string
	ChangedAfter time.Time
}

// SyncItemsResult содержит измененные encrypted vault items и следующий sync cursor
type SyncItemsResult struct {
	Items            []Item
	NextChangedAfter time.Time
}

// Validate проверяет полноту encrypted data перед сохранением или обработкой
func (d *EncryptedData) Validate() error {
	if len(d.Ciphertext) == 0 {
		return fmt.Errorf("%w: ciphertext is required", ErrInvalidInput)
	}

	if len(d.Nonce) == 0 {
		return fmt.Errorf("%w: nonce is required", ErrInvalidInput)
	}

	return nil
}

// Validate проверяет входные данные создания encrypted vault item
func (i *CreateItemInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if i.Type == "" {
		return fmt.Errorf("%w: item type is required", ErrInvalidInput)
	}

	if err := i.Metadata.Validate(); err != nil {
		return err
	}

	if err := i.Payload.Validate(); err != nil {
		return err
	}

	if strings.TrimSpace(i.EncryptionAlg) == "" {
		return fmt.Errorf("%w: encryption algorithm is required", ErrInvalidInput)
	}

	if i.PayloadSchemaVersion == 0 {
		return fmt.Errorf("%w: payload schema version is required", ErrInvalidInput)
	}

	return nil
}

// Validate проверяет входные данные получения encrypted vault item
func (i *GetItemInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if strings.TrimSpace(i.ItemID) == "" {
		return fmt.Errorf("%w: item id is required", ErrInvalidInput)
	}

	return nil
}

// Validate проверяет входные данные получения списка encrypted vault items
func (i *ListItemsInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	return nil
}

// Validate проверяет входные данные обновления encrypted vault item
func (i *UpdateItemInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if strings.TrimSpace(i.ItemID) == "" {
		return fmt.Errorf("%w: item id is required", ErrInvalidInput)
	}

	if i.ExpectedVersion <= 0 {
		return fmt.Errorf("%w: expected version is required", ErrInvalidInput)
	}

	if i.Type == "" {
		return fmt.Errorf("%w: item type is required", ErrInvalidInput)
	}

	if err := i.Metadata.Validate(); err != nil {
		return err
	}

	if err := i.Payload.Validate(); err != nil {
		return err
	}

	if strings.TrimSpace(i.EncryptionAlg) == "" {
		return fmt.Errorf("%w: encryption algorithm is required", ErrInvalidInput)
	}

	if i.PayloadSchemaVersion == 0 {
		return fmt.Errorf("%w: payload schema version is required", ErrInvalidInput)
	}

	return nil
}

// Validate проверяет входные данные soft delete encrypted vault item
func (i *DeleteItemInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if strings.TrimSpace(i.ItemID) == "" {
		return fmt.Errorf("%w: item id is required", ErrInvalidInput)
	}

	if i.ExpectedVersion <= 0 {
		return fmt.Errorf("%w: expected version is required", ErrInvalidInput)
	}

	return nil
}

// Validate проверяет входные данные синхронизации encrypted vault items
func (i *SyncItemsInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	return nil
}
