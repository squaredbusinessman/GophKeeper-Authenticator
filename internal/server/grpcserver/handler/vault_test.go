package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver/authcontext"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/vault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeVaultUseCase struct {
	createFunc func(context.Context, vault.CreateItemInput) (vault.Item, error)
	getFunc    func(context.Context, vault.GetItemInput) (vault.Item, error)
	listFunc   func(context.Context, vault.ListItemsInput) ([]vault.Item, error)
	updateFunc func(context.Context, vault.UpdateItemInput) (vault.Item, error)
	deleteFunc func(context.Context, vault.DeleteItemInput) (vault.DeleteItemResult, error)
	syncFunc   func(context.Context, vault.SyncItemsInput) (vault.SyncItemsResult, error)

	createCalls []vault.CreateItemInput
	getCalls    []vault.GetItemInput
	listCalls   []vault.ListItemsInput
	updateCalls []vault.UpdateItemInput
	deleteCalls []vault.DeleteItemInput
	syncCalls   []vault.SyncItemsInput
}

func (u *fakeVaultUseCase) CreateItem(ctx context.Context, input vault.CreateItemInput) (vault.Item, error) {
	u.createCalls = append(u.createCalls, input)
	if u.createFunc != nil {
		return u.createFunc(ctx, input)
	}

	return validVaultItem(), nil
}

func (u *fakeVaultUseCase) GetItem(ctx context.Context, input vault.GetItemInput) (vault.Item, error) {
	u.getCalls = append(u.getCalls, input)
	if u.getFunc != nil {
		return u.getFunc(ctx, input)
	}

	return validVaultItem(), nil
}

func (u *fakeVaultUseCase) ListItems(ctx context.Context, input vault.ListItemsInput) ([]vault.Item, error) {
	u.listCalls = append(u.listCalls, input)
	if u.listFunc != nil {
		return u.listFunc(ctx, input)
	}

	return []vault.Item{validVaultItem()}, nil
}

func (u *fakeVaultUseCase) UpdateItem(ctx context.Context, input vault.UpdateItemInput) (vault.Item, error) {
	u.updateCalls = append(u.updateCalls, input)
	if u.updateFunc != nil {
		return u.updateFunc(ctx, input)
	}

	item := validVaultItem()
	item.ID = input.ItemID
	item.Type = input.Type
	item.Metadata = input.Metadata
	item.Payload = input.Payload
	item.EncryptionAlg = input.EncryptionAlg
	item.PayloadSchemaVersion = input.PayloadSchemaVersion
	item.Version = input.ExpectedVersion + 1
	return item, nil
}

func (u *fakeVaultUseCase) DeleteItem(ctx context.Context, input vault.DeleteItemInput) (vault.DeleteItemResult, error) {
	u.deleteCalls = append(u.deleteCalls, input)
	if u.deleteFunc != nil {
		return u.deleteFunc(ctx, input)
	}

	return vault.DeleteItemResult{
		ItemID:    input.ItemID,
		Version:   input.ExpectedVersion + 1,
		DeletedAt: time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
	}, nil
}

func (u *fakeVaultUseCase) SyncItems(ctx context.Context, input vault.SyncItemsInput) (vault.SyncItemsResult, error) {
	u.syncCalls = append(u.syncCalls, input)
	if u.syncFunc != nil {
		return u.syncFunc(ctx, input)
	}

	nextChangedAfter := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)
	return vault.SyncItemsResult{
		Items:            []vault.Item{validVaultItem()},
		NextChangedAfter: nextChangedAfter,
	}, nil
}

func validVaultItem() vault.Item {
	return vault.Item{
		ID:     "item-id-1",
		UserID: "user-id-1",
		Type:   vault.ItemTypeLoginPassword,
		Metadata: vault.EncryptedData{
			Ciphertext: []byte("encrypted-metadata"),
			Nonce:      []byte("metadata-nonce"),
		},
		Payload: vault.EncryptedData{
			Ciphertext: []byte("encrypted-payload"),
			Nonce:      []byte("payload-nonce"),
		},
		EncryptionAlg:        "aes-256-gcm",
		PayloadSchemaVersion: 1,
		Version:              7,
		CreatedAt:            time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		UpdatedAt:            time.Date(2026, 5, 19, 12, 5, 0, 0, time.UTC),
	}
}

func validCreateItemRequest() *gophkeeperv1.CreateItemRequest {
	return &gophkeeperv1.CreateItemRequest{
		Type: gophkeeperv1.ItemType_ITEM_TYPE_LOGIN_PASSWORD,
		Metadata: &gophkeeperv1.EncryptedData{
			Ciphertext: []byte("encrypted-metadata"),
			Nonce:      []byte("metadata-nonce"),
		},
		Payload: &gophkeeperv1.EncryptedData{
			Ciphertext: []byte("encrypted-payload"),
			Nonce:      []byte("payload-nonce"),
		},
		EncryptionAlg:        "aes-256-gcm",
		PayloadSchemaVersion: 1,
	}
}

func vaultContext() context.Context {
	return authcontext.ContextWithUserID(context.Background(), "user-id-1")
}

func TestVaultHandlerCreateItemCallsUseCaseAndReturnsItem(t *testing.T) {
	useCase := &fakeVaultUseCase{}
	handler := NewVaultHandler(useCase)

	response, err := handler.CreateItem(vaultContext(), validCreateItemRequest())
	if err != nil {
		t.Fatalf("CreateItem() error = %v", err)
	}

	if response == nil || response.Item == nil {
		t.Fatalf("CreateItem() response item = nil")
	}

	if response.Item.Id != "item-id-1" {
		t.Fatalf("Item.Id = %q, want item-id-1", response.Item.Id)
	}

	if response.Item.Type != gophkeeperv1.ItemType_ITEM_TYPE_LOGIN_PASSWORD {
		t.Fatalf("Item.Type = %s, want ITEM_TYPE_LOGIN_PASSWORD", response.Item.Type)
	}

	if string(response.Item.Metadata.GetCiphertext()) != "encrypted-metadata" {
		t.Fatalf("metadata ciphertext = %q, want encrypted-metadata", string(response.Item.Metadata.GetCiphertext()))
	}

	if string(response.Item.Payload.GetCiphertext()) != "encrypted-payload" {
		t.Fatalf("payload ciphertext = %q, want encrypted-payload", string(response.Item.Payload.GetCiphertext()))
	}

	if response.Item.Version != 7 {
		t.Fatalf("Item.Version = %d, want 7", response.Item.Version)
	}

	if response.Item.CreatedAt == nil {
		t.Fatalf("Item.CreatedAt = nil")
	}

	if len(useCase.createCalls) != 1 {
		t.Fatalf("create calls = %d, want 1", len(useCase.createCalls))
	}

	input := useCase.createCalls[0]
	if input.UserID != "user-id-1" {
		t.Fatalf("input UserID = %q, want user-id-1", input.UserID)
	}

	if input.Type != vault.ItemTypeLoginPassword {
		t.Fatalf("input Type = %q, want %q", input.Type, vault.ItemTypeLoginPassword)
	}

	if string(input.Metadata.Ciphertext) != "encrypted-metadata" {
		t.Fatalf("input metadata ciphertext = %q, want encrypted-metadata", string(input.Metadata.Ciphertext))
	}

	if input.EncryptionAlg != "aes-256-gcm" {
		t.Fatalf("input EncryptionAlg = %q, want aes-256-gcm", input.EncryptionAlg)
	}
}

func TestVaultHandlerGetItemCallsUseCaseAndReturnsItem(t *testing.T) {
	useCase := &fakeVaultUseCase{}
	handler := NewVaultHandler(useCase)

	response, err := handler.GetItem(vaultContext(), &gophkeeperv1.GetItemRequest{Id: "item-id-1"})
	if err != nil {
		t.Fatalf("GetItem() error = %v", err)
	}

	if response == nil || response.Item == nil {
		t.Fatalf("GetItem() response item = nil")
	}

	if response.Item.Id != "item-id-1" {
		t.Fatalf("Item.Id = %q, want item-id-1", response.Item.Id)
	}

	if len(useCase.getCalls) != 1 {
		t.Fatalf("get calls = %d, want 1", len(useCase.getCalls))
	}

	input := useCase.getCalls[0]
	if input.UserID != "user-id-1" {
		t.Fatalf("input UserID = %q, want user-id-1", input.UserID)
	}

	if input.ItemID != "item-id-1" {
		t.Fatalf("input ItemID = %q, want item-id-1", input.ItemID)
	}
}

func TestVaultHandlerListItemsCallsUseCaseAndReturnsItems(t *testing.T) {
	useCase := &fakeVaultUseCase{}
	handler := NewVaultHandler(useCase)

	response, err := handler.ListItems(vaultContext(), &gophkeeperv1.ListItemsRequest{})
	if err != nil {
		t.Fatalf("ListItems() error = %v", err)
	}

	if response == nil {
		t.Fatalf("ListItems() response = nil")
	}

	if len(response.GetItems()) != 1 {
		t.Fatalf("items length = %d, want 1", len(response.GetItems()))
	}

	if response.GetItems()[0].GetId() != "item-id-1" {
		t.Fatalf("item id = %q, want item-id-1", response.GetItems()[0].GetId())
	}

	if len(useCase.listCalls) != 1 {
		t.Fatalf("list calls = %d, want 1", len(useCase.listCalls))
	}

	input := useCase.listCalls[0]
	if input.UserID != "user-id-1" {
		t.Fatalf("input UserID = %q, want user-id-1", input.UserID)
	}

	if input.IncludeDeleted {
		t.Fatalf("IncludeDeleted = true, want false")
	}
}

func TestVaultHandlerUpdateItemCallsUseCaseAndReturnsItem(t *testing.T) {
	useCase := &fakeVaultUseCase{}
	handler := NewVaultHandler(useCase)

	response, err := handler.UpdateItem(vaultContext(), validUpdateItemRequest())
	if err != nil {
		t.Fatalf("UpdateItem() error = %v", err)
	}

	if response == nil || response.Item == nil {
		t.Fatalf("UpdateItem() response item = nil")
	}

	if response.Item.GetVersion() != 8 {
		t.Fatalf("version = %d, want 8", response.Item.GetVersion())
	}

	if len(useCase.updateCalls) != 1 {
		t.Fatalf("update calls = %d, want 1", len(useCase.updateCalls))
	}

	input := useCase.updateCalls[0]
	if input.UserID != "user-id-1" {
		t.Fatalf("input UserID = %q, want user-id-1", input.UserID)
	}

	if input.ItemID != "item-id-1" {
		t.Fatalf("input ItemID = %q, want item-id-1", input.ItemID)
	}

	if input.ExpectedVersion != 7 {
		t.Fatalf("input ExpectedVersion = %d, want 7", input.ExpectedVersion)
	}

	if input.Type != vault.ItemTypeText {
		t.Fatalf("input Type = %q, want text", input.Type)
	}
}

func TestVaultHandlerDeleteItemCallsUseCaseAndReturnsResult(t *testing.T) {
	useCase := &fakeVaultUseCase{}
	handler := NewVaultHandler(useCase)

	response, err := handler.DeleteItem(vaultContext(), &gophkeeperv1.DeleteItemRequest{
		Id:              "item-id-1",
		ExpectedVersion: 7,
	})
	if err != nil {
		t.Fatalf("DeleteItem() error = %v", err)
	}

	if response.GetId() != "item-id-1" {
		t.Fatalf("id = %q, want item-id-1", response.GetId())
	}

	if response.GetVersion() != 8 {
		t.Fatalf("version = %d, want 8", response.GetVersion())
	}

	if response.GetDeletedAt() == nil {
		t.Fatalf("deleted at = nil")
	}

	if len(useCase.deleteCalls) != 1 {
		t.Fatalf("delete calls = %d, want 1", len(useCase.deleteCalls))
	}

	input := useCase.deleteCalls[0]
	if input.UserID != "user-id-1" {
		t.Fatalf("input UserID = %q, want user-id-1", input.UserID)
	}

	if input.ItemID != "item-id-1" {
		t.Fatalf("input ItemID = %q, want item-id-1", input.ItemID)
	}

	if input.ExpectedVersion != 7 {
		t.Fatalf("input ExpectedVersion = %d, want 7", input.ExpectedVersion)
	}
}

func TestVaultHandlerSyncCallsUseCaseAndReturnsChangedItems(t *testing.T) {
	changedAfter := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	deletedAt := time.Date(2026, 5, 20, 14, 30, 0, 0, time.UTC)
	deletedItem := validVaultItem()
	deletedItem.ID = "deleted-item-id"
	deletedItem.UpdatedAt = deletedAt
	deletedItem.DeletedAt = &deletedAt

	useCase := &fakeVaultUseCase{
		syncFunc: func(ctx context.Context, input vault.SyncItemsInput) (vault.SyncItemsResult, error) {
			if input.UserID != "user-id-1" {
				t.Fatalf("input UserID = %q, want user-id-1", input.UserID)
			}

			if !input.ChangedAfter.Equal(changedAfter) {
				t.Fatalf("input ChangedAfter = %s, want %s", input.ChangedAfter, changedAfter)
			}

			return vault.SyncItemsResult{
				Items:            []vault.Item{deletedItem},
				NextChangedAfter: deletedAt,
			}, nil
		},
	}
	handler := NewVaultHandler(useCase)

	response, err := handler.Sync(vaultContext(), &gophkeeperv1.SyncRequest{
		ChangedAfter: timestamppb.New(changedAfter),
	})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if response == nil {
		t.Fatalf("Sync() response = nil")
	}

	if len(response.GetItems()) != 1 {
		t.Fatalf("items length = %d, want 1", len(response.GetItems()))
	}

	item := response.GetItems()[0]
	if item.GetId() != "deleted-item-id" {
		t.Fatalf("item id = %q, want deleted-item-id", item.GetId())
	}

	if item.GetDeletedAt() == nil {
		t.Fatalf("item deleted_at = nil")
	}

	if !item.GetDeletedAt().AsTime().Equal(deletedAt) {
		t.Fatalf("item deleted_at = %s, want %s", item.GetDeletedAt().AsTime(), deletedAt)
	}

	if response.GetNextChangedAfter() == nil {
		t.Fatalf("next_changed_after = nil")
	}

	if !response.GetNextChangedAfter().AsTime().Equal(deletedAt) {
		t.Fatalf("next_changed_after = %s, want %s", response.GetNextChangedAfter().AsTime(), deletedAt)
	}

	if len(useCase.syncCalls) != 1 {
		t.Fatalf("sync calls = %d, want 1", len(useCase.syncCalls))
	}
}

func TestVaultHandlerReturnsUnauthenticatedWhenUserIDMissing(t *testing.T) {
	useCase := &fakeVaultUseCase{}
	handler := NewVaultHandler(useCase)

	_, err := handler.CreateItem(context.Background(), validCreateItemRequest())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("CreateItem() code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}

	_, err = handler.GetItem(context.Background(), &gophkeeperv1.GetItemRequest{Id: "item-id-1"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("GetItem() code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}

	_, err = handler.ListItems(context.Background(), &gophkeeperv1.ListItemsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("ListItems() code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}

	_, err = handler.UpdateItem(context.Background(), validUpdateItemRequest())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("UpdateItem() code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}

	_, err = handler.DeleteItem(context.Background(), &gophkeeperv1.DeleteItemRequest{Id: "item-id-1", ExpectedVersion: 7})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("DeleteItem() code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}

	_, err = handler.Sync(context.Background(), &gophkeeperv1.SyncRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Sync() code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}

	if len(useCase.createCalls) != 0 {
		t.Fatalf("create calls = %d, want 0", len(useCase.createCalls))
	}

	if len(useCase.getCalls) != 0 {
		t.Fatalf("get calls = %d, want 0", len(useCase.getCalls))
	}

	if len(useCase.listCalls) != 0 {
		t.Fatalf("list calls = %d, want 0", len(useCase.listCalls))
	}

	if len(useCase.updateCalls) != 0 {
		t.Fatalf("update calls = %d, want 0", len(useCase.updateCalls))
	}

	if len(useCase.deleteCalls) != 0 {
		t.Fatalf("delete calls = %d, want 0", len(useCase.deleteCalls))
	}

	if len(useCase.syncCalls) != 0 {
		t.Fatalf("sync calls = %d, want 0", len(useCase.syncCalls))
	}
}

func TestVaultHandlerCreateItemReturnsInvalidArgumentForInvalidRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *gophkeeperv1.CreateItemRequest
	}{
		{
			name:    "nil request",
			request: nil,
		},
		{
			name: "unspecified type",
			request: func() *gophkeeperv1.CreateItemRequest {
				request := validCreateItemRequest()
				request.Type = gophkeeperv1.ItemType_ITEM_TYPE_UNSPECIFIED
				return request
			}(),
		},
		{
			name: "nil metadata",
			request: func() *gophkeeperv1.CreateItemRequest {
				request := validCreateItemRequest()
				request.Metadata = nil
				return request
			}(),
		},
		{
			name: "empty metadata ciphertext",
			request: func() *gophkeeperv1.CreateItemRequest {
				request := validCreateItemRequest()
				request.Metadata.Ciphertext = nil
				return request
			}(),
		},
		{
			name: "nil payload",
			request: func() *gophkeeperv1.CreateItemRequest {
				request := validCreateItemRequest()
				request.Payload = nil
				return request
			}(),
		},
		{
			name: "empty payload nonce",
			request: func() *gophkeeperv1.CreateItemRequest {
				request := validCreateItemRequest()
				request.Payload.Nonce = nil
				return request
			}(),
		},
		{
			name: "empty encryption alg",
			request: func() *gophkeeperv1.CreateItemRequest {
				request := validCreateItemRequest()
				request.EncryptionAlg = " "
				return request
			}(),
		},
		{
			name: "zero payload schema version",
			request: func() *gophkeeperv1.CreateItemRequest {
				request := validCreateItemRequest()
				request.PayloadSchemaVersion = 0
				return request
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{}
			handler := NewVaultHandler(useCase)

			_, err := handler.CreateItem(vaultContext(), tt.request)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("CreateItem() code = %s, want %s, err = %v", status.Code(err), codes.InvalidArgument, err)
			}

			if len(useCase.createCalls) != 0 {
				t.Fatalf("create calls = %d, want 0", len(useCase.createCalls))
			}
		})
	}
}

func TestVaultHandlerGetItemReturnsInvalidArgumentForInvalidRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *gophkeeperv1.GetItemRequest
	}{
		{
			name:    "nil request",
			request: nil,
		},
		{
			name:    "empty id",
			request: &gophkeeperv1.GetItemRequest{Id: " "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{}
			handler := NewVaultHandler(useCase)

			_, err := handler.GetItem(vaultContext(), tt.request)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("GetItem() code = %s, want %s, err = %v", status.Code(err), codes.InvalidArgument, err)
			}

			if len(useCase.getCalls) != 0 {
				t.Fatalf("get calls = %d, want 0", len(useCase.getCalls))
			}
		})
	}
}

func TestVaultHandlerUpdateItemReturnsInvalidArgumentForInvalidRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *gophkeeperv1.UpdateItemRequest
	}{
		{
			name:    "nil request",
			request: nil,
		},
		{
			name: "empty id",
			request: func() *gophkeeperv1.UpdateItemRequest {
				request := validUpdateItemRequest()
				request.Id = " "
				return request
			}(),
		},
		{
			name: "zero expected version",
			request: func() *gophkeeperv1.UpdateItemRequest {
				request := validUpdateItemRequest()
				request.ExpectedVersion = 0
				return request
			}(),
		},
		{
			name: "unspecified type",
			request: func() *gophkeeperv1.UpdateItemRequest {
				request := validUpdateItemRequest()
				request.Type = gophkeeperv1.ItemType_ITEM_TYPE_UNSPECIFIED
				return request
			}(),
		},
		{
			name: "nil metadata",
			request: func() *gophkeeperv1.UpdateItemRequest {
				request := validUpdateItemRequest()
				request.Metadata = nil
				return request
			}(),
		},
		{
			name: "nil payload",
			request: func() *gophkeeperv1.UpdateItemRequest {
				request := validUpdateItemRequest()
				request.Payload = nil
				return request
			}(),
		},
		{
			name: "empty encryption alg",
			request: func() *gophkeeperv1.UpdateItemRequest {
				request := validUpdateItemRequest()
				request.EncryptionAlg = " "
				return request
			}(),
		},
		{
			name: "zero payload schema version",
			request: func() *gophkeeperv1.UpdateItemRequest {
				request := validUpdateItemRequest()
				request.PayloadSchemaVersion = 0
				return request
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{}
			handler := NewVaultHandler(useCase)

			_, err := handler.UpdateItem(vaultContext(), tt.request)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("UpdateItem() code = %s, want %s, err = %v", status.Code(err), codes.InvalidArgument, err)
			}

			if len(useCase.updateCalls) != 0 {
				t.Fatalf("update calls = %d, want 0", len(useCase.updateCalls))
			}
		})
	}
}

func TestVaultHandlerDeleteItemReturnsInvalidArgumentForInvalidRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *gophkeeperv1.DeleteItemRequest
	}{
		{
			name:    "nil request",
			request: nil,
		},
		{
			name: "empty id",
			request: &gophkeeperv1.DeleteItemRequest{
				Id:              " ",
				ExpectedVersion: 7,
			},
		},
		{
			name: "zero expected version",
			request: &gophkeeperv1.DeleteItemRequest{
				Id: "item-id-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{}
			handler := NewVaultHandler(useCase)

			_, err := handler.DeleteItem(vaultContext(), tt.request)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("DeleteItem() code = %s, want %s, err = %v", status.Code(err), codes.InvalidArgument, err)
			}

			if len(useCase.deleteCalls) != 0 {
				t.Fatalf("delete calls = %d, want 0", len(useCase.deleteCalls))
			}
		})
	}
}

func TestVaultHandlerMapsUseCaseErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{
			name: "invalid input",
			err:  vault.ErrInvalidInput,
			code: codes.InvalidArgument,
		},
		{
			name: "not found",
			err:  vault.ErrItemNotFound,
			code: codes.NotFound,
		},
		{
			name: "access denied",
			err:  vault.ErrAccessDenied,
			code: codes.PermissionDenied,
		},
		{
			name: "version conflict",
			err:  vault.ErrVersionConflict,
			code: codes.FailedPrecondition,
		},
		{
			name: "internal error",
			err:  errors.New("database failed"),
			code: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run("create "+tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{
				createFunc: func(context.Context, vault.CreateItemInput) (vault.Item, error) {
					return vault.Item{}, tt.err
				},
			}
			handler := NewVaultHandler(useCase)

			_, err := handler.CreateItem(vaultContext(), validCreateItemRequest())
			if status.Code(err) != tt.code {
				t.Fatalf("CreateItem() code = %s, want %s, err = %v", status.Code(err), tt.code, err)
			}
		})

		t.Run("get "+tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{
				getFunc: func(context.Context, vault.GetItemInput) (vault.Item, error) {
					return vault.Item{}, tt.err
				},
			}
			handler := NewVaultHandler(useCase)

			_, err := handler.GetItem(vaultContext(), &gophkeeperv1.GetItemRequest{Id: "item-id-1"})
			if status.Code(err) != tt.code {
				t.Fatalf("GetItem() code = %s, want %s, err = %v", status.Code(err), tt.code, err)
			}
		})

		t.Run("list "+tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{
				listFunc: func(context.Context, vault.ListItemsInput) ([]vault.Item, error) {
					return nil, tt.err
				},
			}
			handler := NewVaultHandler(useCase)

			_, err := handler.ListItems(vaultContext(), &gophkeeperv1.ListItemsRequest{})
			if status.Code(err) != tt.code {
				t.Fatalf("ListItems() code = %s, want %s, err = %v", status.Code(err), tt.code, err)
			}
		})

		t.Run("update "+tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{
				updateFunc: func(context.Context, vault.UpdateItemInput) (vault.Item, error) {
					return vault.Item{}, tt.err
				},
			}
			handler := NewVaultHandler(useCase)

			_, err := handler.UpdateItem(vaultContext(), validUpdateItemRequest())
			if status.Code(err) != tt.code {
				t.Fatalf("UpdateItem() code = %s, want %s, err = %v", status.Code(err), tt.code, err)
			}
		})

		t.Run("delete "+tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{
				deleteFunc: func(context.Context, vault.DeleteItemInput) (vault.DeleteItemResult, error) {
					return vault.DeleteItemResult{}, tt.err
				},
			}
			handler := NewVaultHandler(useCase)

			_, err := handler.DeleteItem(vaultContext(), &gophkeeperv1.DeleteItemRequest{Id: "item-id-1", ExpectedVersion: 7})
			if status.Code(err) != tt.code {
				t.Fatalf("DeleteItem() code = %s, want %s, err = %v", status.Code(err), tt.code, err)
			}
		})

		t.Run("sync "+tt.name, func(t *testing.T) {
			useCase := &fakeVaultUseCase{
				syncFunc: func(context.Context, vault.SyncItemsInput) (vault.SyncItemsResult, error) {
					return vault.SyncItemsResult{}, tt.err
				},
			}
			handler := NewVaultHandler(useCase)

			_, err := handler.Sync(vaultContext(), &gophkeeperv1.SyncRequest{})
			if status.Code(err) != tt.code {
				t.Fatalf("Sync() code = %s, want %s, err = %v", status.Code(err), tt.code, err)
			}
		})
	}
}

func validUpdateItemRequest() *gophkeeperv1.UpdateItemRequest {
	return &gophkeeperv1.UpdateItemRequest{
		Id:              "item-id-1",
		ExpectedVersion: 7,
		Type:            gophkeeperv1.ItemType_ITEM_TYPE_TEXT,
		Metadata: &gophkeeperv1.EncryptedData{
			Ciphertext: []byte("updated-encrypted-metadata"),
			Nonce:      []byte("updated-metadata-nonce"),
		},
		Payload: &gophkeeperv1.EncryptedData{
			Ciphertext: []byte("updated-encrypted-payload"),
			Nonce:      []byte("updated-payload-nonce"),
		},
		EncryptionAlg:        "aes-256-gcm",
		PayloadSchemaVersion: 2,
	}
}
