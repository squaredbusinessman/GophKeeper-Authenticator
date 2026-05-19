package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type fakeRepository struct {
	createFunc func(context.Context, CreateItemParams) (Item, error)
	findFunc   func(context.Context, string) (Item, error)

	createCalls []CreateItemParams
	findCalls   []string
}

func (r *fakeRepository) CreateItem(ctx context.Context, params CreateItemParams) (Item, error) {
	r.createCalls = append(r.createCalls, params)
	if r.createFunc != nil {
		return r.createFunc(ctx, params)
	}

	return Item{
		ID:                   params.ItemID,
		UserID:               params.UserID,
		Type:                 params.Type,
		Metadata:             params.Metadata,
		Payload:              params.Payload,
		EncryptionAlg:        params.EncryptionAlg,
		PayloadSchemaVersion: params.PayloadSchemaVersion,
		Version:              1,
		CreatedAt:            time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		UpdatedAt:            time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
	}, nil
}

func (r *fakeRepository) FindItemByID(ctx context.Context, itemID string) (Item, error) {
	r.findCalls = append(r.findCalls, itemID)
	if r.findFunc != nil {
		return r.findFunc(ctx, itemID)
	}

	return validItem(), nil
}

type fakeIDGenerator struct {
	id  string
	err error
}

func (g fakeIDGenerator) NewID() (string, error) {
	if g.err != nil {
		return "", g.err
	}

	return g.id, nil
}

func validCreateInput() CreateItemInput {
	return CreateItemInput{
		UserID: "user-id-1",
		Type:   ItemTypeLoginPassword,
		Metadata: EncryptedData{
			Ciphertext: []byte("encrypted-metadata"),
			Nonce:      []byte("metadata-nonce"),
		},
		Payload: EncryptedData{
			Ciphertext: []byte("encrypted-payload"),
			Nonce:      []byte("payload-nonce"),
		},
		EncryptionAlg:        "aes-256-gcm",
		PayloadSchemaVersion: 1,
	}
}

func validItem() Item {
	return Item{
		ID:     "item-id-1",
		UserID: "user-id-1",
		Type:   ItemTypeLoginPassword,
		Metadata: EncryptedData{
			Ciphertext: []byte("encrypted-metadata"),
			Nonce:      []byte("metadata-nonce"),
		},
		Payload: EncryptedData{
			Ciphertext: []byte("encrypted-payload"),
			Nonce:      []byte("payload-nonce"),
		},
		EncryptionAlg:        "aes-256-gcm",
		PayloadSchemaVersion: 1,
		Version:              1,
		CreatedAt:            time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		UpdatedAt:            time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
	}
}

func newTestService(repository Repository) *Service {
	return NewService(repository, fakeIDGenerator{id: "item-id-1"})
}

func TestServiceCreateItemStoresEncryptedItem(t *testing.T) {
	repository := &fakeRepository{}
	service := newTestService(repository)

	item, err := service.CreateItem(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreateItem() error = %v", err)
	}

	if item.ID != "item-id-1" {
		t.Fatalf("ID = %q, want item-id-1", item.ID)
	}

	if item.UserID != "user-id-1" {
		t.Fatalf("UserID = %q, want user-id-1", item.UserID)
	}

	if item.Version != 1 {
		t.Fatalf("Version = %d, want 1", item.Version)
	}

	if len(repository.createCalls) != 1 {
		t.Fatalf("repository create calls = %d, want 1", len(repository.createCalls))
	}

	params := repository.createCalls[0]
	if params.ItemID != "item-id-1" {
		t.Fatalf("ItemID = %q, want generated item id", params.ItemID)
	}

	if params.UserID != "user-id-1" {
		t.Fatalf("UserID = %q, want input user id", params.UserID)
	}

	if params.Type != ItemTypeLoginPassword {
		t.Fatalf("Type = %q, want %q", params.Type, ItemTypeLoginPassword)
	}

	if !bytes.Equal(params.Metadata.Ciphertext, []byte("encrypted-metadata")) {
		t.Fatalf("Metadata ciphertext does not match input")
	}

	if !bytes.Equal(params.Metadata.Nonce, []byte("metadata-nonce")) {
		t.Fatalf("Metadata nonce does not match input")
	}

	if !bytes.Equal(params.Payload.Ciphertext, []byte("encrypted-payload")) {
		t.Fatalf("Payload ciphertext does not match input")
	}

	if !bytes.Equal(params.Payload.Nonce, []byte("payload-nonce")) {
		t.Fatalf("Payload nonce does not match input")
	}

	if params.EncryptionAlg != "aes-256-gcm" {
		t.Fatalf("EncryptionAlg = %q, want aes-256-gcm", params.EncryptionAlg)
	}

	if params.PayloadSchemaVersion != 1 {
		t.Fatalf("PayloadSchemaVersion = %d, want 1", params.PayloadSchemaVersion)
	}
}

func TestServiceCreateItemReturnsErrorForInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input CreateItemInput
	}{
		{
			name: "empty user id",
			input: func() CreateItemInput {
				input := validCreateInput()
				input.UserID = " "
				return input
			}(),
		},
		{
			name: "empty type",
			input: func() CreateItemInput {
				input := validCreateInput()
				input.Type = ""
				return input
			}(),
		},
		{
			name: "empty metadata ciphertext",
			input: func() CreateItemInput {
				input := validCreateInput()
				input.Metadata.Ciphertext = nil
				return input
			}(),
		},
		{
			name: "empty metadata nonce",
			input: func() CreateItemInput {
				input := validCreateInput()
				input.Metadata.Nonce = nil
				return input
			}(),
		},
		{
			name: "empty payload ciphertext",
			input: func() CreateItemInput {
				input := validCreateInput()
				input.Payload.Ciphertext = nil
				return input
			}(),
		},
		{
			name: "empty payload nonce",
			input: func() CreateItemInput {
				input := validCreateInput()
				input.Payload.Nonce = nil
				return input
			}(),
		},
		{
			name: "empty encryption alg",
			input: func() CreateItemInput {
				input := validCreateInput()
				input.EncryptionAlg = " "
				return input
			}(),
		},
		{
			name: "zero payload schema version",
			input: func() CreateItemInput {
				input := validCreateInput()
				input.PayloadSchemaVersion = 0
				return input
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := &fakeRepository{}
			service := newTestService(repository)

			_, err := service.CreateItem(context.Background(), tt.input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("CreateItem() error = %v, want ErrInvalidInput", err)
			}

			if len(repository.createCalls) != 0 {
				t.Fatalf("repository create calls = %d, want 0", len(repository.createCalls))
			}
		})
	}
}

func TestServiceCreateItemReturnsErrorWhenIDGenerationFails(t *testing.T) {
	idErr := errors.New("id generation failed")
	repository := &fakeRepository{}
	service := NewService(repository, fakeIDGenerator{err: idErr})

	_, err := service.CreateItem(context.Background(), validCreateInput())
	if !errors.Is(err, idErr) {
		t.Fatalf("CreateItem() error = %v, want id generation error", err)
	}

	if len(repository.createCalls) != 0 {
		t.Fatalf("repository create calls = %d, want 0", len(repository.createCalls))
	}
}

func TestServiceCreateItemReturnsRepositoryError(t *testing.T) {
	createErr := errors.New("create failed")
	repository := &fakeRepository{
		createFunc: func(context.Context, CreateItemParams) (Item, error) {
			return Item{}, createErr
		},
	}
	service := newTestService(repository)

	_, err := service.CreateItem(context.Background(), validCreateInput())
	if !errors.Is(err, createErr) {
		t.Fatalf("CreateItem() error = %v, want create error", err)
	}
}

func TestServiceGetItemReturnsOwnedItem(t *testing.T) {
	repository := &fakeRepository{}
	service := newTestService(repository)

	item, err := service.GetItem(context.Background(), GetItemInput{
		UserID: "user-id-1",
		ItemID: "item-id-1",
	})
	if err != nil {
		t.Fatalf("GetItem() error = %v", err)
	}

	if item.ID != "item-id-1" {
		t.Fatalf("ID = %q, want item-id-1", item.ID)
	}

	if len(repository.findCalls) != 1 || repository.findCalls[0] != "item-id-1" {
		t.Fatalf("repository find calls = %v, want item-id-1", repository.findCalls)
	}
}

func TestServiceGetItemReturnsAccessDeniedForDifferentOwner(t *testing.T) {
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.UserID = "another-user-id"
			return item, nil
		},
	}
	service := newTestService(repository)

	_, err := service.GetItem(context.Background(), GetItemInput{
		UserID: "user-id-1",
		ItemID: "item-id-1",
	})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("GetItem() error = %v, want ErrAccessDenied", err)
	}
}

func TestServiceGetItemReturnsNotFound(t *testing.T) {
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			return Item{}, ErrItemNotFound
		},
	}
	service := newTestService(repository)

	_, err := service.GetItem(context.Background(), GetItemInput{
		UserID: "user-id-1",
		ItemID: "missing-item-id",
	})
	if !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("GetItem() error = %v, want ErrItemNotFound", err)
	}
}

func TestServiceGetItemReturnsErrorForInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input GetItemInput
	}{
		{
			name: "empty user id",
			input: GetItemInput{
				ItemID: "item-id-1",
			},
		},
		{
			name: "empty item id",
			input: GetItemInput{
				UserID: "user-id-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := &fakeRepository{}
			service := newTestService(repository)

			_, err := service.GetItem(context.Background(), tt.input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("GetItem() error = %v, want ErrInvalidInput", err)
			}

			if len(repository.findCalls) != 0 {
				t.Fatalf("repository find calls = %d, want 0", len(repository.findCalls))
			}
		})
	}
}
