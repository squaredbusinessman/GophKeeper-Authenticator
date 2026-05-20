package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver/authcontext"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/vault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VaultUseCase описывает use case для операций с encrypted vault items
type VaultUseCase interface {
	CreateItem(context.Context, vault.CreateItemInput) (vault.Item, error)
	GetItem(context.Context, vault.GetItemInput) (vault.Item, error)
	ListItems(context.Context, vault.ListItemsInput) ([]vault.Item, error)
	UpdateItem(context.Context, vault.UpdateItemInput) (vault.Item, error)
	DeleteItem(context.Context, vault.DeleteItemInput) (vault.DeleteItemResult, error)
}

// VaultHandler обрабатывает запросы сервиса хранилища
type VaultHandler struct {
	gophkeeperv1.UnimplementedVaultServiceServer

	vaultUseCase VaultUseCase
}

// NewVaultHandler создает обработчик сервиса хранилища
func NewVaultHandler(vaultUseCase VaultUseCase) *VaultHandler {
	return &VaultHandler{
		vaultUseCase: vaultUseCase,
	}
}

// CreateItem создает encrypted vault item через gRPC API
func (h *VaultHandler) CreateItem(ctx context.Context, req *gophkeeperv1.CreateItemRequest) (*gophkeeperv1.CreateItemResponse, error) {
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user id is required")
	}

	input, err := createItemInputFromProto(userID, req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if h.vaultUseCase == nil {
		return nil, status.Error(codes.Internal, "vault use case is not configured")
	}

	item, err := h.vaultUseCase.CreateItem(ctx, input)
	if err != nil {
		return nil, vaultStatusError(err)
	}

	return &gophkeeperv1.CreateItemResponse{
		Item: vaultItemToProto(item),
	}, nil
}

// GetItem возвращает encrypted vault item через gRPC API
func (h *VaultHandler) GetItem(ctx context.Context, req *gophkeeperv1.GetItemRequest) (*gophkeeperv1.GetItemResponse, error) {
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user id is required")
	}

	input, err := getItemInputFromProto(userID, req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if h.vaultUseCase == nil {
		return nil, status.Error(codes.Internal, "vault use case is not configured")
	}

	item, err := h.vaultUseCase.GetItem(ctx, input)
	if err != nil {
		return nil, vaultStatusError(err)
	}

	return &gophkeeperv1.GetItemResponse{
		Item: vaultItemToProto(item),
	}, nil
}

// ListItems возвращает encrypted vault items через gRPC API
func (h *VaultHandler) ListItems(ctx context.Context, req *gophkeeperv1.ListItemsRequest) (*gophkeeperv1.ListItemsResponse, error) {
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user id is required")
	}

	if h.vaultUseCase == nil {
		return nil, status.Error(codes.Internal, "vault use case is not configured")
	}

	items, err := h.vaultUseCase.ListItems(ctx, vault.ListItemsInput{
		UserID:         userID,
		IncludeDeleted: req.GetIncludeDeleted(),
	})
	if err != nil {
		return nil, vaultStatusError(err)
	}

	response := &gophkeeperv1.ListItemsResponse{
		Items: make([]*gophkeeperv1.VaultItem, 0, len(items)),
	}

	for _, item := range items {
		response.Items = append(response.Items, vaultItemToProto(item))
	}

	return response, nil
}

// UpdateItem обновляет encrypted vault item через gRPC API
func (h *VaultHandler) UpdateItem(ctx context.Context, req *gophkeeperv1.UpdateItemRequest) (*gophkeeperv1.UpdateItemResponse, error) {
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user id is required")
	}

	input, err := updateItemInputFromProto(userID, req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if h.vaultUseCase == nil {
		return nil, status.Error(codes.Internal, "vault use case is not configured")
	}

	item, err := h.vaultUseCase.UpdateItem(ctx, input)
	if err != nil {
		return nil, vaultStatusError(err)
	}

	return &gophkeeperv1.UpdateItemResponse{
		Item: vaultItemToProto(item),
	}, nil
}

// DeleteItem мягко удаляет vault item через gRPC API
func (h *VaultHandler) DeleteItem(ctx context.Context, req *gophkeeperv1.DeleteItemRequest) (*gophkeeperv1.DeleteItemResponse, error) {
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user id is required")
	}

	input, err := deleteItemInputFromProto(userID, req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if h.vaultUseCase == nil {
		return nil, status.Error(codes.Internal, "vault use case is not configured")
	}

	result, err := h.vaultUseCase.DeleteItem(ctx, input)
	if err != nil {
		return nil, vaultStatusError(err)
	}

	return &gophkeeperv1.DeleteItemResponse{
		Id:        result.ItemID,
		Version:   result.Version,
		DeletedAt: timestamppb.New(result.DeletedAt),
	}, nil
}

func createItemInputFromProto(userID string, req *gophkeeperv1.CreateItemRequest) (vault.CreateItemInput, error) {
	if req == nil {
		return vault.CreateItemInput{}, fmt.Errorf("create item request is required")
	}

	if req.GetType() == gophkeeperv1.ItemType_ITEM_TYPE_UNSPECIFIED {
		return vault.CreateItemInput{}, fmt.Errorf("item type is required")
	}

	metadata, err := encryptedDataFromProto(req.GetMetadata(), "metadata")
	if err != nil {
		return vault.CreateItemInput{}, err
	}

	payload, err := encryptedDataFromProto(req.GetPayload(), "payload")
	if err != nil {
		return vault.CreateItemInput{}, err
	}

	if strings.TrimSpace(req.GetEncryptionAlg()) == "" {
		return vault.CreateItemInput{}, fmt.Errorf("encryption algorithm is required")
	}

	if req.GetPayloadSchemaVersion() == 0 {
		return vault.CreateItemInput{}, fmt.Errorf("payload schema version is required")
	}

	return vault.CreateItemInput{
		UserID:               userID,
		Type:                 itemTypeFromProto(req.GetType()),
		Metadata:             metadata,
		Payload:              payload,
		EncryptionAlg:        req.GetEncryptionAlg(),
		PayloadSchemaVersion: req.GetPayloadSchemaVersion(),
	}, nil
}

func getItemInputFromProto(userID string, req *gophkeeperv1.GetItemRequest) (vault.GetItemInput, error) {
	if req == nil {
		return vault.GetItemInput{}, fmt.Errorf("get item request is required")
	}

	if strings.TrimSpace(req.GetId()) == "" {
		return vault.GetItemInput{}, fmt.Errorf("item id is required")
	}

	return vault.GetItemInput{
		UserID: userID,
		ItemID: req.GetId(),
	}, nil
}

func updateItemInputFromProto(userID string, req *gophkeeperv1.UpdateItemRequest) (vault.UpdateItemInput, error) {
	if req == nil {
		return vault.UpdateItemInput{}, fmt.Errorf("update item request is required")
	}

	if strings.TrimSpace(req.GetId()) == "" {
		return vault.UpdateItemInput{}, fmt.Errorf("item id is required")
	}

	if req.GetExpectedVersion() <= 0 {
		return vault.UpdateItemInput{}, fmt.Errorf("expected version is required")
	}

	if req.GetType() == gophkeeperv1.ItemType_ITEM_TYPE_UNSPECIFIED {
		return vault.UpdateItemInput{}, fmt.Errorf("item type is required")
	}

	metadata, err := encryptedDataFromProto(req.GetMetadata(), "metadata")
	if err != nil {
		return vault.UpdateItemInput{}, err
	}

	payload, err := encryptedDataFromProto(req.GetPayload(), "payload")
	if err != nil {
		return vault.UpdateItemInput{}, err
	}

	if strings.TrimSpace(req.GetEncryptionAlg()) == "" {
		return vault.UpdateItemInput{}, fmt.Errorf("encryption algorithm is required")
	}

	if req.GetPayloadSchemaVersion() == 0 {
		return vault.UpdateItemInput{}, fmt.Errorf("payload schema version is required")
	}

	return vault.UpdateItemInput{
		UserID:               userID,
		ItemID:               req.GetId(),
		ExpectedVersion:      req.GetExpectedVersion(),
		Type:                 itemTypeFromProto(req.GetType()),
		Metadata:             metadata,
		Payload:              payload,
		EncryptionAlg:        req.GetEncryptionAlg(),
		PayloadSchemaVersion: req.GetPayloadSchemaVersion(),
	}, nil
}

func deleteItemInputFromProto(userID string, req *gophkeeperv1.DeleteItemRequest) (vault.DeleteItemInput, error) {
	if req == nil {
		return vault.DeleteItemInput{}, fmt.Errorf("delete item request is required")
	}

	if strings.TrimSpace(req.GetId()) == "" {
		return vault.DeleteItemInput{}, fmt.Errorf("item id is required")
	}

	if req.GetExpectedVersion() <= 0 {
		return vault.DeleteItemInput{}, fmt.Errorf("expected version is required")
	}

	return vault.DeleteItemInput{
		UserID:          userID,
		ItemID:          req.GetId(),
		ExpectedVersion: req.GetExpectedVersion(),
	}, nil
}

func encryptedDataFromProto(data *gophkeeperv1.EncryptedData, fieldName string) (vault.EncryptedData, error) {
	if data == nil {
		return vault.EncryptedData{}, fmt.Errorf("%s is required", fieldName)
	}

	if len(data.GetCiphertext()) == 0 {
		return vault.EncryptedData{}, fmt.Errorf("%s ciphertext is required", fieldName)
	}

	if len(data.GetNonce()) == 0 {
		return vault.EncryptedData{}, fmt.Errorf("%s nonce is required", fieldName)
	}

	return vault.EncryptedData{
		Ciphertext: data.GetCiphertext(),
		Nonce:      data.GetNonce(),
	}, nil
}

func vaultItemToProto(item vault.Item) *gophkeeperv1.VaultItem {
	return &gophkeeperv1.VaultItem{
		Id:   item.ID,
		Type: itemTypeToProto(item.Type),
		Metadata: &gophkeeperv1.EncryptedData{
			Ciphertext: item.Metadata.Ciphertext,
			Nonce:      item.Metadata.Nonce,
		},
		Payload: &gophkeeperv1.EncryptedData{
			Ciphertext: item.Payload.Ciphertext,
			Nonce:      item.Payload.Nonce,
		},
		EncryptionAlg:        item.EncryptionAlg,
		PayloadSchemaVersion: item.PayloadSchemaVersion,
		Version:              item.Version,
		CreatedAt:            timestamppb.New(item.CreatedAt),
		UpdatedAt:            timestamppb.New(item.UpdatedAt),
		DeletedAt:            deletedAtToProto(item),
	}
}

func deletedAtToProto(item vault.Item) *timestamppb.Timestamp {
	if item.DeletedAt == nil {
		return nil
	}

	return timestamppb.New(*item.DeletedAt)
}

func itemTypeFromProto(itemType gophkeeperv1.ItemType) vault.ItemType {
	switch itemType {
	case gophkeeperv1.ItemType_ITEM_TYPE_LOGIN_PASSWORD:
		return vault.ItemTypeLoginPassword
	case gophkeeperv1.ItemType_ITEM_TYPE_TEXT:
		return vault.ItemTypeText
	case gophkeeperv1.ItemType_ITEM_TYPE_BINARY:
		return vault.ItemTypeBinary
	case gophkeeperv1.ItemType_ITEM_TYPE_BANK_CARD:
		return vault.ItemTypeBankCard
	default:
		return ""
	}
}

func itemTypeToProto(itemType vault.ItemType) gophkeeperv1.ItemType {
	switch itemType {
	case vault.ItemTypeLoginPassword:
		return gophkeeperv1.ItemType_ITEM_TYPE_LOGIN_PASSWORD
	case vault.ItemTypeText:
		return gophkeeperv1.ItemType_ITEM_TYPE_TEXT
	case vault.ItemTypeBinary:
		return gophkeeperv1.ItemType_ITEM_TYPE_BINARY
	case vault.ItemTypeBankCard:
		return gophkeeperv1.ItemType_ITEM_TYPE_BANK_CARD
	default:
		return gophkeeperv1.ItemType_ITEM_TYPE_UNSPECIFIED
	}
}

func vaultStatusError(err error) error {
	switch {
	case errors.Is(err, vault.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, vault.ErrItemNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, vault.ErrAccessDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, vault.ErrVersionConflict):
		return status.Error(codes.Aborted, err.Error())
	default:
		return status.Error(codes.Internal, "vault operation failed")
	}
}
