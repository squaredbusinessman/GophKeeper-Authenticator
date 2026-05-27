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
	listFunc   func(context.Context, ListItemsParams) ([]Item, error)
	updateFunc func(context.Context, UpdateItemParams) (Item, error)
	deleteFunc func(context.Context, DeleteItemParams) (DeleteItemResult, error)
	syncFunc   func(context.Context, SyncItemsParams) (SyncItemsResult, error)

	createCalls []CreateItemParams
	findCalls   []string
	listCalls   []ListItemsParams
	updateCalls []UpdateItemParams
	deleteCalls []DeleteItemParams
	syncCalls   []SyncItemsParams
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

func (r *fakeRepository) ListItems(ctx context.Context, params ListItemsParams) ([]Item, error) {
	r.listCalls = append(r.listCalls, params)
	if r.listFunc != nil {
		return r.listFunc(ctx, params)
	}

	return []Item{validItem()}, nil
}

func (r *fakeRepository) UpdateItem(ctx context.Context, params UpdateItemParams) (Item, error) {
	r.updateCalls = append(r.updateCalls, params)
	if r.updateFunc != nil {
		return r.updateFunc(ctx, params)
	}

	item := validItem()
	item.Type = params.Type
	item.Metadata = params.Metadata
	item.Payload = params.Payload
	item.EncryptionAlg = params.EncryptionAlg
	item.PayloadSchemaVersion = params.PayloadSchemaVersion
	item.Version = params.ExpectedVersion + 1
	item.UpdatedAt = time.Date(2026, 5, 20, 12, 30, 0, 0, time.UTC)
	return item, nil
}

func (r *fakeRepository) DeleteItem(ctx context.Context, params DeleteItemParams) (DeleteItemResult, error) {
	r.deleteCalls = append(r.deleteCalls, params)
	if r.deleteFunc != nil {
		return r.deleteFunc(ctx, params)
	}

	return DeleteItemResult{
		ItemID:    params.ItemID,
		Version:   params.ExpectedVersion + 1,
		DeletedAt: time.Date(2026, 5, 20, 13, 0, 0, 0, time.UTC),
	}, nil
}

func (r *fakeRepository) SyncItems(ctx context.Context, params SyncItemsParams) (SyncItemsResult, error) {
	r.syncCalls = append(r.syncCalls, params)
	if r.syncFunc != nil {
		return r.syncFunc(ctx, params)
	}

	return SyncItemsResult{
		Items:            []Item{validItem()},
		NextChangedAfter: time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC),
	}, nil
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

func TestServiceListItemsReturnsOwnedItems(t *testing.T) {
	repository := &fakeRepository{
		listFunc: func(_ context.Context, params ListItemsParams) ([]Item, error) {
			if params.UserID != "user-id-1" {
				t.Fatalf("UserID = %q, want user-id-1", params.UserID)
			}

			if params.IncludeDeleted {
				t.Fatalf("IncludeDeleted = true, want false")
			}

			return []Item{validItem()}, nil
		},
	}
	service := newTestService(repository)

	items, err := service.ListItems(context.Background(), ListItemsInput{
		UserID: " user-id-1 ",
	})
	if err != nil {
		t.Fatalf("ListItems() error = %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("items length = %d, want 1", len(items))
	}

	if len(repository.listCalls) != 1 {
		t.Fatalf("repository list calls = %d, want 1", len(repository.listCalls))
	}
}

func TestServiceListItemsReturnsErrorForInvalidInput(t *testing.T) {
	repository := &fakeRepository{}
	service := newTestService(repository)

	_, err := service.ListItems(context.Background(), ListItemsInput{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("ListItems() error = %v, want ErrInvalidInput", err)
	}

	if len(repository.listCalls) != 0 {
		t.Fatalf("repository list calls = %d, want 0", len(repository.listCalls))
	}
}

func TestServiceUpdateItemUpdatesOwnedItemWithExpectedVersion(t *testing.T) {
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.Version = 3
			return item, nil
		},
	}
	service := newTestService(repository)
	input := validUpdateInput()

	item, err := service.UpdateItem(context.Background(), input)
	if err != nil {
		t.Fatalf("UpdateItem() error = %v", err)
	}

	if item.Version != 4 {
		t.Fatalf("Version = %d, want 4", item.Version)
	}

	if len(repository.findCalls) != 1 || repository.findCalls[0] != "item-id-1" {
		t.Fatalf("repository find calls = %v, want item-id-1", repository.findCalls)
	}

	if len(repository.updateCalls) != 1 {
		t.Fatalf("repository update calls = %d, want 1", len(repository.updateCalls))
	}

	params := repository.updateCalls[0]
	if params.UserID != "user-id-1" {
		t.Fatalf("UserID = %q, want user-id-1", params.UserID)
	}

	if params.ExpectedVersion != 3 {
		t.Fatalf("ExpectedVersion = %d, want 3", params.ExpectedVersion)
	}

	if params.Type != ItemTypeText {
		t.Fatalf("Type = %q, want %q", params.Type, ItemTypeText)
	}
}

func TestServiceUpdateItemReturnsVersionConflict(t *testing.T) {
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.Version = 4
			return item, nil
		},
	}
	service := newTestService(repository)
	input := validUpdateInput()
	input.ExpectedVersion = 3

	_, err := service.UpdateItem(context.Background(), input)
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("UpdateItem() error = %v, want ErrVersionConflict", err)
	}

	if len(repository.updateCalls) != 0 {
		t.Fatalf("repository update calls = %d, want 0", len(repository.updateCalls))
	}
}

func TestServiceUpdateItemReturnsNotFoundWhenItemIsDeleted(t *testing.T) {
	deletedAt := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.Version = 3
			item.DeletedAt = &deletedAt
			return item, nil
		},
	}
	service := newTestService(repository)

	_, err := service.UpdateItem(context.Background(), validUpdateInput())
	if !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("UpdateItem() error = %v, want ErrItemNotFound", err)
	}

	if len(repository.updateCalls) != 0 {
		t.Fatalf("repository update calls = %d, want 0", len(repository.updateCalls))
	}
}

func TestServiceUpdateItemReturnsNotFoundWhenItemIsDeletedDuringUpdate(t *testing.T) {
	deletedAt := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)
	findCalls := 0
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			findCalls++
			item := validItem()
			item.Version = 3
			if findCalls > 1 {
				item.DeletedAt = &deletedAt
			}
			return item, nil
		},
		updateFunc: func(context.Context, UpdateItemParams) (Item, error) {
			return Item{}, ErrVersionConflict
		},
	}
	service := newTestService(repository)

	_, err := service.UpdateItem(context.Background(), validUpdateInput())
	if !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("UpdateItem() error = %v, want ErrItemNotFound", err)
	}

	if len(repository.updateCalls) != 1 {
		t.Fatalf("repository update calls = %d, want 1", len(repository.updateCalls))
	}
}

func TestServiceUpdateItemReturnsAccessDeniedForDifferentOwner(t *testing.T) {
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.UserID = "another-user-id"
			return item, nil
		},
	}
	service := newTestService(repository)

	_, err := service.UpdateItem(context.Background(), validUpdateInput())
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("UpdateItem() error = %v, want ErrAccessDenied", err)
	}

	if len(repository.updateCalls) != 0 {
		t.Fatalf("repository update calls = %d, want 0", len(repository.updateCalls))
	}
}

func TestServiceUpdateItemReturnsErrorForInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input UpdateItemInput
	}{
		{
			name: "empty user id",
			input: func() UpdateItemInput {
				input := validUpdateInput()
				input.UserID = " "
				return input
			}(),
		},
		{
			name: "empty item id",
			input: func() UpdateItemInput {
				input := validUpdateInput()
				input.ItemID = " "
				return input
			}(),
		},
		{
			name: "zero expected version",
			input: func() UpdateItemInput {
				input := validUpdateInput()
				input.ExpectedVersion = 0
				return input
			}(),
		},
		{
			name: "empty payload ciphertext",
			input: func() UpdateItemInput {
				input := validUpdateInput()
				input.Payload.Ciphertext = nil
				return input
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := &fakeRepository{}
			service := newTestService(repository)

			_, err := service.UpdateItem(context.Background(), tt.input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("UpdateItem() error = %v, want ErrInvalidInput", err)
			}

			if len(repository.findCalls) != 0 {
				t.Fatalf("repository find calls = %d, want 0", len(repository.findCalls))
			}
		})
	}
}

func TestServiceDeleteItemSoftDeletesOwnedItemWithExpectedVersion(t *testing.T) {
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.Version = 5
			return item, nil
		},
	}
	service := newTestService(repository)

	result, err := service.DeleteItem(context.Background(), DeleteItemInput{
		UserID:          " user-id-1 ",
		ItemID:          " item-id-1 ",
		ExpectedVersion: 5,
	})
	if err != nil {
		t.Fatalf("DeleteItem() error = %v", err)
	}

	if result.ItemID != "item-id-1" {
		t.Fatalf("ItemID = %q, want item-id-1", result.ItemID)
	}

	if result.Version != 6 {
		t.Fatalf("Version = %d, want 6", result.Version)
	}

	if result.DeletedAt.IsZero() {
		t.Fatalf("DeletedAt is zero")
	}

	if len(repository.deleteCalls) != 1 {
		t.Fatalf("repository delete calls = %d, want 1", len(repository.deleteCalls))
	}

	params := repository.deleteCalls[0]
	if params.ExpectedVersion != 5 {
		t.Fatalf("ExpectedVersion = %d, want 5", params.ExpectedVersion)
	}
}

func TestServiceDeleteItemReturnsVersionConflict(t *testing.T) {
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.Version = 6
			return item, nil
		},
	}
	service := newTestService(repository)

	_, err := service.DeleteItem(context.Background(), DeleteItemInput{
		UserID:          "user-id-1",
		ItemID:          "item-id-1",
		ExpectedVersion: 5,
	})
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("DeleteItem() error = %v, want ErrVersionConflict", err)
	}

	if len(repository.deleteCalls) != 0 {
		t.Fatalf("repository delete calls = %d, want 0", len(repository.deleteCalls))
	}
}

func TestServiceDeleteItemReturnsNotFoundWhenItemIsDeleted(t *testing.T) {
	deletedAt := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.Version = 5
			item.DeletedAt = &deletedAt
			return item, nil
		},
	}
	service := newTestService(repository)

	_, err := service.DeleteItem(context.Background(), DeleteItemInput{
		UserID:          "user-id-1",
		ItemID:          "item-id-1",
		ExpectedVersion: 5,
	})
	if !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("DeleteItem() error = %v, want ErrItemNotFound", err)
	}

	if len(repository.deleteCalls) != 0 {
		t.Fatalf("repository delete calls = %d, want 0", len(repository.deleteCalls))
	}
}

func TestServiceDeleteItemReturnsNotFoundWhenItemIsDeletedDuringDelete(t *testing.T) {
	deletedAt := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)
	findCalls := 0
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			findCalls++
			item := validItem()
			item.Version = 5
			if findCalls > 1 {
				item.DeletedAt = &deletedAt
			}
			return item, nil
		},
		deleteFunc: func(context.Context, DeleteItemParams) (DeleteItemResult, error) {
			return DeleteItemResult{}, ErrVersionConflict
		},
	}
	service := newTestService(repository)

	_, err := service.DeleteItem(context.Background(), DeleteItemInput{
		UserID:          "user-id-1",
		ItemID:          "item-id-1",
		ExpectedVersion: 5,
	})
	if !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("DeleteItem() error = %v, want ErrItemNotFound", err)
	}

	if len(repository.deleteCalls) != 1 {
		t.Fatalf("repository delete calls = %d, want 1", len(repository.deleteCalls))
	}
}

func TestServiceDeleteItemReturnsAccessDeniedForDifferentOwner(t *testing.T) {
	repository := &fakeRepository{
		findFunc: func(context.Context, string) (Item, error) {
			item := validItem()
			item.UserID = "another-user-id"
			return item, nil
		},
	}
	service := newTestService(repository)

	_, err := service.DeleteItem(context.Background(), DeleteItemInput{
		UserID:          "user-id-1",
		ItemID:          "item-id-1",
		ExpectedVersion: 1,
	})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("DeleteItem() error = %v, want ErrAccessDenied", err)
	}

	if len(repository.deleteCalls) != 0 {
		t.Fatalf("repository delete calls = %d, want 0", len(repository.deleteCalls))
	}
}

func TestServiceDeleteItemReturnsErrorForInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input DeleteItemInput
	}{
		{
			name: "empty user id",
			input: DeleteItemInput{
				ItemID:          "item-id-1",
				ExpectedVersion: 1,
			},
		},
		{
			name: "empty item id",
			input: DeleteItemInput{
				UserID:          "user-id-1",
				ExpectedVersion: 1,
			},
		},
		{
			name: "zero expected version",
			input: DeleteItemInput{
				UserID: "user-id-1",
				ItemID: "item-id-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := &fakeRepository{}
			service := newTestService(repository)

			_, err := service.DeleteItem(context.Background(), tt.input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("DeleteItem() error = %v, want ErrInvalidInput", err)
			}

			if len(repository.findCalls) != 0 {
				t.Fatalf("repository find calls = %d, want 0", len(repository.findCalls))
			}
		})
	}
}

func TestServiceSyncItemsReturnsChangedItemsIncludingDeleted(t *testing.T) {
	changedAfter := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	deletedAt := time.Date(2026, 5, 20, 11, 0, 0, 0, time.UTC)
	deletedItem := validItem()
	deletedItem.ID = "deleted-item-id"
	deletedItem.DeletedAt = &deletedAt
	deletedItem.UpdatedAt = deletedAt

	repository := &fakeRepository{
		syncFunc: func(_ context.Context, params SyncItemsParams) (SyncItemsResult, error) {
			if params.UserID != "user-id-1" {
				t.Fatalf("UserID = %q, want user-id-1", params.UserID)
			}

			if !params.ChangedAfter.Equal(changedAfter) {
				t.Fatalf("ChangedAfter = %s, want %s", params.ChangedAfter, changedAfter)
			}

			return SyncItemsResult{
				Items:            []Item{deletedItem},
				NextChangedAfter: deletedAt,
			}, nil
		},
	}
	service := newTestService(repository)

	result, err := service.SyncItems(context.Background(), SyncItemsInput{
		UserID:       " user-id-1 ",
		ChangedAfter: changedAfter,
	})
	if err != nil {
		t.Fatalf("SyncItems() error = %v", err)
	}

	if len(result.Items) != 1 {
		t.Fatalf("items length = %d, want 1", len(result.Items))
	}

	if result.Items[0].DeletedAt == nil {
		t.Fatalf("DeletedAt = nil, want tombstone")
	}

	if !result.NextChangedAfter.Equal(deletedAt) {
		t.Fatalf("NextChangedAfter = %s, want %s", result.NextChangedAfter, deletedAt)
	}

	if len(repository.syncCalls) != 1 {
		t.Fatalf("sync calls = %d, want 1", len(repository.syncCalls))
	}
}

func TestServiceSyncItemsReturnsErrorForInvalidInput(t *testing.T) {
	repository := &fakeRepository{}
	service := newTestService(repository)

	_, err := service.SyncItems(context.Background(), SyncItemsInput{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("SyncItems() error = %v, want ErrInvalidInput", err)
	}

	if len(repository.syncCalls) != 0 {
		t.Fatalf("sync calls = %d, want 0", len(repository.syncCalls))
	}
}

func validUpdateInput() UpdateItemInput {
	return UpdateItemInput{
		UserID:          "user-id-1",
		ItemID:          "item-id-1",
		ExpectedVersion: 3,
		Type:            ItemTypeText,
		Metadata: EncryptedData{
			Ciphertext: []byte("updated-encrypted-metadata"),
			Nonce:      []byte("updated-metadata-nonce"),
		},
		Payload: EncryptedData{
			Ciphertext: []byte("updated-encrypted-payload"),
			Nonce:      []byte("updated-payload-nonce"),
		},
		EncryptionAlg:        "aes-256-gcm",
		PayloadSchemaVersion: 2,
	}
}
