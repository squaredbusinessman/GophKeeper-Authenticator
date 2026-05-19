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
)

type fakeVaultUseCase struct {
	createFunc func(context.Context, vault.CreateItemInput) (vault.Item, error)
	getFunc    func(context.Context, vault.GetItemInput) (vault.Item, error)

	createCalls []vault.CreateItemInput
	getCalls    []vault.GetItemInput
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

	if len(useCase.createCalls) != 0 {
		t.Fatalf("create calls = %d, want 0", len(useCase.createCalls))
	}

	if len(useCase.getCalls) != 0 {
		t.Fatalf("get calls = %d, want 0", len(useCase.getCalls))
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
	}
}
