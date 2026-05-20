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

type ItemType string

const (
	ItemTypeLoginPassword ItemType = "login_password"
	ItemTypeText          ItemType = "text"
	ItemTypeBinary        ItemType = "binary"
	ItemTypeBankCard      ItemType = "bank_card"
)

type EncryptedData struct {
	Ciphertext []byte
	Nonce      []byte
}

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

type CreateItemInput struct {
	UserID               string
	Type                 ItemType
	Metadata             EncryptedData
	Payload              EncryptedData
	EncryptionAlg        string
	PayloadSchemaVersion uint32
}

type GetItemInput struct {
	UserID string
	ItemID string
}

type CreateItemParams struct {
	ItemID               string
	UserID               string
	Type                 ItemType
	Metadata             EncryptedData
	Payload              EncryptedData
	EncryptionAlg        string
	PayloadSchemaVersion uint32
}

type ListItemsInput struct {
	UserID         string
	IncludeDeleted bool
}

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

type DeleteItemInput struct {
	UserID          string
	ItemID          string
	ExpectedVersion int64
}

type ListItemsParams struct {
	UserID         string
	IncludeDeleted bool
}

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

type DeleteItemParams struct {
	ItemID          string
	UserID          string
	ExpectedVersion int64
}

type DeleteItemResult struct {
	ItemID    string
	Version   int64
	DeletedAt time.Time
}

type SyncItemsInput struct {
	UserID       string
	ChangedAfter time.Time
}

type SyncItemsParams struct {
	UserID       string
	ChangedAfter time.Time
}

type SyncItemsResult struct {
	Items            []Item
	NextChangedAfter time.Time
}

func (d *EncryptedData) Validate() error {
	if len(d.Ciphertext) == 0 {
		return fmt.Errorf("%w: ciphertext is required", ErrInvalidInput)
	}

	if len(d.Nonce) == 0 {
		return fmt.Errorf("%w: nonce is required", ErrInvalidInput)
	}

	return nil
}

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

func (i *GetItemInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if strings.TrimSpace(i.ItemID) == "" {
		return fmt.Errorf("%w: item id is required", ErrInvalidInput)
	}

	return nil
}

func (i *ListItemsInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	return nil
}

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

func (i *SyncItemsInput) Validate() error {
	if strings.TrimSpace(i.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	return nil
}
