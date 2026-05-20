package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/crypto/payload"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VaultServiceClient описывает gRPC-клиент vault API, который нужен client core
type VaultServiceClient interface {
	CreateItem(context.Context, *gophkeeperv1.CreateItemRequest, ...grpc.CallOption) (*gophkeeperv1.CreateItemResponse, error)
	GetItem(context.Context, *gophkeeperv1.GetItemRequest, ...grpc.CallOption) (*gophkeeperv1.GetItemResponse, error)
	ListItems(context.Context, *gophkeeperv1.ListItemsRequest, ...grpc.CallOption) (*gophkeeperv1.ListItemsResponse, error)
	UpdateItem(context.Context, *gophkeeperv1.UpdateItemRequest, ...grpc.CallOption) (*gophkeeperv1.UpdateItemResponse, error)
	DeleteItem(context.Context, *gophkeeperv1.DeleteItemRequest, ...grpc.CallOption) (*gophkeeperv1.DeleteItemResponse, error)
	Sync(context.Context, *gophkeeperv1.SyncRequest, ...grpc.CallOption) (*gophkeeperv1.SyncResponse, error)
}

// SecretType описывает тип секрета внутри client core без прямой зависимости UI от proto enum
type SecretType int

const (
	// SecretTypeUnspecified означает, что тип секрета не задан
	SecretTypeUnspecified SecretType = iota

	// SecretTypeLoginPassword хранит пару логин и пароль
	SecretTypeLoginPassword

	// SecretTypeText хранит произвольный текстовый секрет
	SecretTypeText

	// SecretTypeBinary хранит произвольные бинарные данные
	SecretTypeBinary

	// SecretTypeBankCard хранит данные банковской карты
	SecretTypeBankCard
)

// CreateSecretInput содержит plaintext-данные секрета для создания
type CreateSecretInput struct {
	Type                 SecretType
	Metadata             []byte
	Payload              []byte
	PayloadSchemaVersion uint32
}

// GetSecretInput содержит данные для получения секрета
type GetSecretInput struct {
	ID string
}

// Secret содержит расшифрованный секрет и серверные поля записи
type Secret struct {
	ID                   string
	Type                 SecretType
	Metadata             []byte
	Payload              []byte
	PayloadSchemaVersion uint32
	Version              int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DeletedAt            *time.Time
}

type ListSecretsInput struct {
	IncludeDeleted bool
}

type SyncSecretsInput struct {
	ChangedAfter time.Time
}

type SyncSecretsResult struct {
	Secrets          []Secret
	NextChangedAfter time.Time
}

type UpdateSecretInput struct {
	ID                   string
	ExpectedVersion      int64
	Type                 SecretType
	Metadata             []byte
	Payload              []byte
	PayloadSchemaVersion uint32
}

type DeleteSecretInput struct {
	ID              string
	ExpectedVersion int64
}

type DeleteSecretResult struct {
	ID        string
	Version   int64
	DeletedAt time.Time
}

// VaultService выполняет client vault flow без UI-логики
type VaultService struct {
	vaultClient VaultServiceClient
}

// NewVaultService создает client vault core
func NewVaultService(vaultClient VaultServiceClient) *VaultService {
	return &VaultService{vaultClient: vaultClient}
}

// CreateSecret шифрует plaintext-данные и создает запись через vault API
func (s *VaultService) CreateSecret(ctx context.Context, session Session, input CreateSecretInput) (Secret, error) {
	if err := s.validateDependencies(); err != nil {
		return Secret{}, err
	}

	if err := validateSession(session); err != nil {
		return Secret{}, err
	}

	if err := input.validate(); err != nil {
		return Secret{}, err
	}

	encryptedMetadata, err := payload.Encrypt(session.VaultKey, input.Metadata)
	if err != nil {
		return Secret{}, fmt.Errorf("encrypt metadata: %w", err)
	}

	encryptedPayload, err := payload.Encrypt(session.VaultKey, input.Payload)
	if err != nil {
		return Secret{}, fmt.Errorf("encrypt payload: %w", err)
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	response, err := s.vaultClient.CreateItem(ctx, &gophkeeperv1.CreateItemRequest{
		Type:                 secretTypeToProto(input.Type),
		Metadata:             encryptedDataToProto(encryptedMetadata),
		Payload:              encryptedDataToProto(encryptedPayload),
		EncryptionAlg:        payload.EncryptionAlgorithm,
		PayloadSchemaVersion: input.PayloadSchemaVersion,
	})
	if err != nil {
		return Secret{}, fmt.Errorf("create secret: %w", err)
	}

	return secretFromProto(session.VaultKey, response.GetItem())
}

// GetSecret получает запись через vault API и расшифровывает payload на клиенте
func (s *VaultService) GetSecret(ctx context.Context, session Session, input GetSecretInput) (Secret, error) {
	if err := s.validateDependencies(); err != nil {
		return Secret{}, err
	}

	if err := validateSession(session); err != nil {
		return Secret{}, err
	}

	if err := input.validate(); err != nil {
		return Secret{}, err
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	response, err := s.vaultClient.GetItem(ctx, &gophkeeperv1.GetItemRequest{
		Id: strings.TrimSpace(input.ID),
	})
	if err != nil {
		return Secret{}, fmt.Errorf("get secret: %w", err)
	}

	return secretFromProto(session.VaultKey, response.GetItem())
}

func (s *VaultService) validateDependencies() error {
	if s.vaultClient == nil {
		return fmt.Errorf("vault client is required")
	}

	return nil
}

func (i *CreateSecretInput) validate() error {
	if i.Type == SecretTypeUnspecified {
		return fmt.Errorf("secret type is required")
	}

	if i.PayloadSchemaVersion == 0 {
		return fmt.Errorf("payload schema version is required")
	}

	return nil
}

func (i *GetSecretInput) validate() error {
	if strings.TrimSpace(i.ID) == "" {
		return fmt.Errorf("secret id is required")
	}

	return nil
}

func validateSession(session Session) error {
	if strings.TrimSpace(session.AccessToken) == "" {
		return fmt.Errorf("access token is required")
	}

	if len(session.VaultKey) != payload.KeyLength {
		return fmt.Errorf("vault key must be %d bytes", payload.KeyLength)
	}

	return nil
}

func contextWithAccessToken(ctx context.Context, accessToken string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)
}

func secretFromProto(vaultKey []byte, item *gophkeeperv1.VaultItem) (Secret, error) {
	if item == nil {
		return Secret{}, fmt.Errorf("vault item is required")
	}

	if item.GetEncryptionAlg() != payload.EncryptionAlgorithm {
		return Secret{}, fmt.Errorf("unsupported payload encryption algorithm: %s", item.GetEncryptionAlg())
	}

	metadataPlaintext, err := payload.Decrypt(vaultKey, encryptedDataFromProto(item.GetMetadata()))
	if err != nil {
		return Secret{}, fmt.Errorf("decrypt metadata: %w", err)
	}

	payloadPlaintext, err := payload.Decrypt(vaultKey, encryptedDataFromProto(item.GetPayload()))
	if err != nil {
		return Secret{}, fmt.Errorf("decrypt payload: %w", err)
	}

	return Secret{
		ID:                   item.GetId(),
		Type:                 secretTypeFromProto(item.GetType()),
		Metadata:             metadataPlaintext,
		Payload:              payloadPlaintext,
		PayloadSchemaVersion: item.GetPayloadSchemaVersion(),
		Version:              item.GetVersion(),
		CreatedAt:            timestampToTime(item.GetCreatedAt()),
		UpdatedAt:            timestampToTime(item.GetUpdatedAt()),
		DeletedAt:            timestampToTimePtr(item.GetDeletedAt()),
	}, nil
}

func encryptedDataToProto(data payload.EncryptedPayload) *gophkeeperv1.EncryptedData {
	return &gophkeeperv1.EncryptedData{
		Ciphertext: data.Ciphertext,
		Nonce:      data.Nonce,
	}
}

func encryptedDataFromProto(data *gophkeeperv1.EncryptedData) payload.EncryptedPayload {
	if data == nil {
		return payload.EncryptedPayload{}
	}

	return payload.EncryptedPayload{
		Ciphertext: data.GetCiphertext(),
		Nonce:      data.GetNonce(),
	}
}

func secretTypeToProto(secretType SecretType) gophkeeperv1.ItemType {
	switch secretType {
	case SecretTypeLoginPassword:
		return gophkeeperv1.ItemType_ITEM_TYPE_LOGIN_PASSWORD
	case SecretTypeText:
		return gophkeeperv1.ItemType_ITEM_TYPE_TEXT
	case SecretTypeBinary:
		return gophkeeperv1.ItemType_ITEM_TYPE_BINARY
	case SecretTypeBankCard:
		return gophkeeperv1.ItemType_ITEM_TYPE_BANK_CARD
	default:
		return gophkeeperv1.ItemType_ITEM_TYPE_UNSPECIFIED
	}
}

func secretTypeFromProto(itemType gophkeeperv1.ItemType) SecretType {
	switch itemType {
	case gophkeeperv1.ItemType_ITEM_TYPE_LOGIN_PASSWORD:
		return SecretTypeLoginPassword
	case gophkeeperv1.ItemType_ITEM_TYPE_TEXT:
		return SecretTypeText
	case gophkeeperv1.ItemType_ITEM_TYPE_BINARY:
		return SecretTypeBinary
	case gophkeeperv1.ItemType_ITEM_TYPE_BANK_CARD:
		return SecretTypeBankCard
	default:
		return SecretTypeUnspecified
	}
}

func timestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}

	return ts.AsTime()
}

func timestampToTimePtr(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}

	value := ts.AsTime()
	return &value
}

// ListSecrets получает список секретов и расшифровывает active items на клиенте
func (s *VaultService) ListSecrets(ctx context.Context, session Session, input ListSecretsInput) ([]Secret, error) {
	if err := s.validateDependencies(); err != nil {
		return nil, err
	}

	if err := validateSession(session); err != nil {
		return nil, err
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	response, err := s.vaultClient.ListItems(ctx, &gophkeeperv1.ListItemsRequest{
		IncludeDeleted: input.IncludeDeleted,
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	secrets := make([]Secret, 0, len(response.GetItems()))
	for _, item := range response.GetItems() {
		// это defensive boundary
		if !input.IncludeDeleted && item.GetDeletedAt() != nil {
			continue
		}

		secret, err := secretFromProto(session.VaultKey, item)
		if err != nil {
			return nil, fmt.Errorf("decode listed secret: %w", err)
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// UpdateSecret шифрует новые plaintext-данные и обновляет секрет с expected version
func (s *VaultService) UpdateSecret(ctx context.Context, session Session, input UpdateSecretInput) (Secret, error) {
	if err := s.validateDependencies(); err != nil {
		return Secret{}, err
	}

	if err := validateSession(session); err != nil {
		return Secret{}, err
	}

	if err := input.validate(); err != nil {
		return Secret{}, err
	}

	encryptedMetadata, err := payload.Encrypt(session.VaultKey, input.Metadata)
	if err != nil {
		return Secret{}, fmt.Errorf("encrypt metadata: %w", err)
	}

	encryptedPayload, err := payload.Encrypt(session.VaultKey, input.Payload)
	if err != nil {
		return Secret{}, fmt.Errorf("encrypt payload: %w", err)
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	response, err := s.vaultClient.UpdateItem(ctx, &gophkeeperv1.UpdateItemRequest{
		Id:                   strings.TrimSpace(input.ID),
		ExpectedVersion:      input.ExpectedVersion,
		Type:                 secretTypeToProto(input.Type),
		Metadata:             encryptedDataToProto(encryptedMetadata),
		Payload:              encryptedDataToProto(encryptedPayload),
		EncryptionAlg:        payload.EncryptionAlgorithm,
		PayloadSchemaVersion: input.PayloadSchemaVersion,
	})
	if err != nil {
		return Secret{}, fmt.Errorf("update secret: %w", err)
	}

	return secretFromProto(session.VaultKey, response.GetItem())
}

// DeleteSecret мягко удаляет секрет с expected version
func (s *VaultService) DeleteSecret(ctx context.Context, session Session, input DeleteSecretInput) (DeleteSecretResult, error) {
	if err := s.validateDependencies(); err != nil {
		return DeleteSecretResult{}, err
	}

	if err := validateSession(session); err != nil {
		return DeleteSecretResult{}, err
	}

	if err := input.validate(); err != nil {
		return DeleteSecretResult{}, err
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	response, err := s.vaultClient.DeleteItem(ctx, &gophkeeperv1.DeleteItemRequest{
		Id:              strings.TrimSpace(input.ID),
		ExpectedVersion: input.ExpectedVersion,
	})
	if err != nil {
		return DeleteSecretResult{}, fmt.Errorf("delete secret: %w", err)
	}

	if strings.TrimSpace(response.GetId()) == "" {
		return DeleteSecretResult{}, fmt.Errorf("deleted secret id is required")
	}

	if response.GetVersion() <= 0 {
		return DeleteSecretResult{}, fmt.Errorf("deleted secret version is required")
	}

	if response.GetDeletedAt() == nil {
		return DeleteSecretResult{}, fmt.Errorf("deleted secret timestamp is required")
	}

	return DeleteSecretResult{
		ID:        response.GetId(),
		Version:   response.GetVersion(),
		DeletedAt: response.GetDeletedAt().AsTime(),
	}, nil
}

func (i *UpdateSecretInput) validate() error {
	if strings.TrimSpace(i.ID) == "" {
		return fmt.Errorf("secret id is required")
	}

	if i.ExpectedVersion <= 0 {
		return fmt.Errorf("expected version is required")
	}

	if i.Type == SecretTypeUnspecified {
		return fmt.Errorf("secret type is required")
	}

	if i.PayloadSchemaVersion == 0 {
		return fmt.Errorf("payload schema version is required")
	}

	return nil
}

func (i *DeleteSecretInput) validate() error {
	if strings.TrimSpace(i.ID) == "" {
		return fmt.Errorf("secret id is required")
	}

	if i.ExpectedVersion <= 0 {
		return fmt.Errorf("expected version is required")
	}

	return nil
}

// SyncSecrets получает изменения с сервера и расшифровывает их на клиенте
func (s *VaultService) SyncSecrets(ctx context.Context, session Session, input SyncSecretsInput) (SyncSecretsResult, error) {
	if err := s.validateDependencies(); err != nil {
		return SyncSecretsResult{}, err
	}

	if err := validateSession(session); err != nil {
		return SyncSecretsResult{}, err
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	request := &gophkeeperv1.SyncRequest{}
	if !input.ChangedAfter.IsZero() {
		request.ChangedAfter = timestamppb.New(input.ChangedAfter)
	}

	response, err := s.vaultClient.Sync(ctx, request)
	if err != nil {
		return SyncSecretsResult{}, fmt.Errorf("sync secrets: %w", err)
	}

	secrets := make([]Secret, 0, len(response.GetItems()))
	for _, item := range response.GetItems() {
		secret, err := secretFromProto(session.VaultKey, item)
		if err != nil {
			return SyncSecretsResult{}, fmt.Errorf("decode synced secret: %w", err)
		}

		secrets = append(secrets, secret)
	}

	return SyncSecretsResult{
		Secrets:          secrets,
		NextChangedAfter: timestampToTime(response.GetNextChangedAfter()),
	}, nil
}
