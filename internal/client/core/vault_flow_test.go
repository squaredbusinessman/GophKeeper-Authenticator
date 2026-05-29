package core

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/crypto/payload"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/crypto/vaultkey"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeVaultClient struct {
	createItemFunc func(context.Context, *gophkeeperv1.CreateItemRequest, ...grpc.CallOption) (*gophkeeperv1.CreateItemResponse, error)
	getItemFunc    func(context.Context, *gophkeeperv1.GetItemRequest, ...grpc.CallOption) (*gophkeeperv1.GetItemResponse, error)
	listItemsFunc  func(context.Context, *gophkeeperv1.ListItemsRequest, ...grpc.CallOption) (*gophkeeperv1.ListItemsResponse, error)
	updateItemFunc func(context.Context, *gophkeeperv1.UpdateItemRequest, ...grpc.CallOption) (*gophkeeperv1.UpdateItemResponse, error)
	deleteItemFunc func(context.Context, *gophkeeperv1.DeleteItemRequest, ...grpc.CallOption) (*gophkeeperv1.DeleteItemResponse, error)
	syncFunc       func(context.Context, *gophkeeperv1.SyncRequest, ...grpc.CallOption) (*gophkeeperv1.SyncResponse, error)

	createItemCalls []vaultClientCall[*gophkeeperv1.CreateItemRequest]
	getItemCalls    []vaultClientCall[*gophkeeperv1.GetItemRequest]
	listItemsCalls  []vaultClientCall[*gophkeeperv1.ListItemsRequest]
	updateItemCalls []vaultClientCall[*gophkeeperv1.UpdateItemRequest]
	deleteItemCalls []vaultClientCall[*gophkeeperv1.DeleteItemRequest]
	syncCalls       []vaultClientCall[*gophkeeperv1.SyncRequest]
}

type vaultClientCall[T any] struct {
	ctx context.Context
	req T
}

func (c *fakeVaultClient) CreateItem(ctx context.Context, req *gophkeeperv1.CreateItemRequest, opts ...grpc.CallOption) (*gophkeeperv1.CreateItemResponse, error) {
	c.createItemCalls = append(c.createItemCalls, vaultClientCall[*gophkeeperv1.CreateItemRequest]{
		ctx: ctx,
		req: req,
	})
	if c.createItemFunc != nil {
		return c.createItemFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected create item call")
}

func (c *fakeVaultClient) GetItem(ctx context.Context, req *gophkeeperv1.GetItemRequest, opts ...grpc.CallOption) (*gophkeeperv1.GetItemResponse, error) {
	c.getItemCalls = append(c.getItemCalls, vaultClientCall[*gophkeeperv1.GetItemRequest]{
		ctx: ctx,
		req: req,
	})
	if c.getItemFunc != nil {
		return c.getItemFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected get item call")
}

func (c *fakeVaultClient) ListItems(ctx context.Context, req *gophkeeperv1.ListItemsRequest, opts ...grpc.CallOption) (*gophkeeperv1.ListItemsResponse, error) {
	c.listItemsCalls = append(c.listItemsCalls, vaultClientCall[*gophkeeperv1.ListItemsRequest]{
		ctx: ctx,
		req: req,
	})
	if c.listItemsFunc != nil {
		return c.listItemsFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected list items call")
}

func (c *fakeVaultClient) UpdateItem(ctx context.Context, req *gophkeeperv1.UpdateItemRequest, opts ...grpc.CallOption) (*gophkeeperv1.UpdateItemResponse, error) {
	c.updateItemCalls = append(c.updateItemCalls, vaultClientCall[*gophkeeperv1.UpdateItemRequest]{
		ctx: ctx,
		req: req,
	})
	if c.updateItemFunc != nil {
		return c.updateItemFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected update item call")
}

func (c *fakeVaultClient) DeleteItem(ctx context.Context, req *gophkeeperv1.DeleteItemRequest, opts ...grpc.CallOption) (*gophkeeperv1.DeleteItemResponse, error) {
	c.deleteItemCalls = append(c.deleteItemCalls, vaultClientCall[*gophkeeperv1.DeleteItemRequest]{
		ctx: ctx,
		req: req,
	})
	if c.deleteItemFunc != nil {
		return c.deleteItemFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected delete item call")
}

func (c *fakeVaultClient) Sync(ctx context.Context, req *gophkeeperv1.SyncRequest, opts ...grpc.CallOption) (*gophkeeperv1.SyncResponse, error) {
	c.syncCalls = append(c.syncCalls, vaultClientCall[*gophkeeperv1.SyncRequest]{
		ctx: ctx,
		req: req,
	})
	if c.syncFunc != nil {
		return c.syncFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected sync call")
}

func TestVaultServiceCreateSecretEncryptsPayloadAndSendsAccessToken(t *testing.T) {
	session := testSession()
	createdAt := time.Date(2026, 5, 19, 13, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 5, 19, 13, 5, 0, 0, time.UTC)
	metadataPlaintext := []byte(`{"title":"work account"}`)
	payloadPlaintext := []byte(`{"login":"user@example.com","password":"secret-password"}`)

	vaultClient := &fakeVaultClient{
		createItemFunc: func(_ context.Context, req *gophkeeperv1.CreateItemRequest, _ ...grpc.CallOption) (*gophkeeperv1.CreateItemResponse, error) {
			assertEncryptedDataDecrypts(t, session.VaultKey, req.GetMetadata(), metadataPlaintext)
			assertEncryptedDataDecrypts(t, session.VaultKey, req.GetPayload(), payloadPlaintext)

			return gophkeeperv1.CreateItemResponse_builder{
				Item: gophkeeperv1.VaultItem_builder{
					Id:                   "item-id-1",
					Type:                 req.GetType(),
					Metadata:             req.GetMetadata(),
					Payload:              req.GetPayload(),
					EncryptionAlg:        req.GetEncryptionAlg(),
					PayloadSchemaVersion: req.GetPayloadSchemaVersion(),
					Version:              1,
					CreatedAt:            timestamppb.New(createdAt),
					UpdatedAt:            timestamppb.New(updatedAt),
				}.Build(),
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	secret, err := service.CreateSecret(context.Background(), session, CreateSecretInput{
		Type:                 SecretTypeLoginPassword,
		Metadata:             metadataPlaintext,
		Payload:              payloadPlaintext,
		PayloadSchemaVersion: 1,
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	if len(vaultClient.createItemCalls) != 1 {
		t.Fatalf("CreateItem() calls = %d, want 1", len(vaultClient.createItemCalls))
	}

	call := vaultClient.createItemCalls[0]
	assertOutgoingBearerToken(call.ctx, t, session.AccessToken)

	request := call.req
	if request.GetType() != gophkeeperv1.ItemType_ITEM_TYPE_LOGIN_PASSWORD {
		t.Fatalf("request type = %s, want login password", request.GetType())
	}

	if request.GetEncryptionAlg() != payload.EncryptionAlgorithm {
		t.Fatalf("request encryption alg = %q, want %q", request.GetEncryptionAlg(), payload.EncryptionAlgorithm)
	}

	if request.GetPayloadSchemaVersion() != 1 {
		t.Fatalf("request schema version = %d, want 1", request.GetPayloadSchemaVersion())
	}

	if bytes.Equal(request.GetPayload().GetCiphertext(), payloadPlaintext) {
		t.Fatalf("request payload ciphertext must not equal plaintext")
	}

	if secret.ID != "item-id-1" {
		t.Fatalf("secret id = %q, want item-id-1", secret.ID)
	}

	if secret.Type != SecretTypeLoginPassword {
		t.Fatalf("secret type = %v, want login password", secret.Type)
	}

	if !bytes.Equal(secret.Metadata, metadataPlaintext) {
		t.Fatalf("secret metadata does not match original plaintext")
	}

	if !bytes.Equal(secret.Payload, payloadPlaintext) {
		t.Fatalf("secret payload does not match original plaintext")
	}

	if secret.Version != 1 {
		t.Fatalf("secret version = %d, want 1", secret.Version)
	}

	if !secret.CreatedAt.Equal(createdAt) {
		t.Fatalf("secret created at = %s, want %s", secret.CreatedAt, createdAt)
	}
}

func TestVaultServiceSupportsOTPSecretType(t *testing.T) {
	session := testSession()
	metadataPlaintext := []byte(`{"title":"Example user@example.com"}`)
	payloadPlaintext, schemaVersion, err := EncodeOTPPayload(OTPPayload{
		Issuer:      "Example",
		AccountName: "user@example.com",
		Secret:      "BASE32SECRET",
		Algorithm:   "SHA1",
		Digits:      6,
	})
	if err != nil {
		t.Fatalf("EncodeOTPPayload() error = %v", err)
	}

	vaultClient := &fakeVaultClient{
		createItemFunc: func(_ context.Context, req *gophkeeperv1.CreateItemRequest, _ ...grpc.CallOption) (*gophkeeperv1.CreateItemResponse, error) {
			if req.GetType() != gophkeeperv1.ItemType_ITEM_TYPE_OTP {
				t.Fatalf("request type = %s, want ITEM_TYPE_OTP", req.GetType())
			}

			return gophkeeperv1.CreateItemResponse_builder{
				Item: gophkeeperv1.VaultItem_builder{
					Id:                   "otp-id-1",
					Type:                 req.GetType(),
					Metadata:             req.GetMetadata(),
					Payload:              req.GetPayload(),
					EncryptionAlg:        req.GetEncryptionAlg(),
					PayloadSchemaVersion: req.GetPayloadSchemaVersion(),
					Version:              1,
				}.Build(),
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	secret, err := service.CreateSecret(context.Background(), session, CreateSecretInput{
		Type:                 SecretTypeOTP,
		Metadata:             metadataPlaintext,
		Payload:              payloadPlaintext,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	if secret.Type != SecretTypeOTP {
		t.Fatalf("secret type = %v, want otp", secret.Type)
	}

	otpPayload, err := DecodeOTPPayload(secret.Payload, secret.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("DecodeOTPPayload() error = %v", err)
	}

	if otpPayload.Secret != "BASE32SECRET" {
		t.Fatalf("otp secret = %q, want BASE32SECRET", otpPayload.Secret)
	}
}

func TestVaultServiceGetSecretDecryptsPayloadAndSendsAccessToken(t *testing.T) {
	session := testSession()
	metadataPlaintext := []byte(`{"title":"api token"}`)
	payloadPlaintext := []byte(`{"token":"secret-api-token"}`)

	encryptedMetadata, err := payload.Encrypt(session.VaultKey, metadataPlaintext)
	if err != nil {
		t.Fatalf("encrypt metadata: %v", err)
	}

	encryptedPayload, err := payload.Encrypt(session.VaultKey, payloadPlaintext)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	vaultClient := &fakeVaultClient{
		getItemFunc: func(_ context.Context, req *gophkeeperv1.GetItemRequest, _ ...grpc.CallOption) (*gophkeeperv1.GetItemResponse, error) {
			if req.GetId() != "item-id-1" {
				t.Fatalf("request id = %q, want item-id-1", req.GetId())
			}

			return gophkeeperv1.GetItemResponse_builder{
				Item: gophkeeperv1.VaultItem_builder{
					Id:                   "item-id-1",
					Type:                 gophkeeperv1.ItemType_ITEM_TYPE_TEXT,
					Metadata:             encryptedDataToProto(encryptedMetadata),
					Payload:              encryptedDataToProto(encryptedPayload),
					EncryptionAlg:        payload.EncryptionAlgorithm,
					PayloadSchemaVersion: 1,
					Version:              3,
				}.Build(),
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	secret, err := service.GetSecret(context.Background(), session, GetSecretInput{ID: "item-id-1"})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}

	if len(vaultClient.getItemCalls) != 1 {
		t.Fatalf("GetItem() calls = %d, want 1", len(vaultClient.getItemCalls))
	}

	assertOutgoingBearerToken(vaultClient.getItemCalls[0].ctx, t, session.AccessToken)

	if secret.ID != "item-id-1" {
		t.Fatalf("secret id = %q, want item-id-1", secret.ID)
	}

	if secret.Type != SecretTypeText {
		t.Fatalf("secret type = %v, want text", secret.Type)
	}

	if !bytes.Equal(secret.Metadata, metadataPlaintext) {
		t.Fatalf("secret metadata does not match original plaintext")
	}

	if !bytes.Equal(secret.Payload, payloadPlaintext) {
		t.Fatalf("secret payload does not match original plaintext")
	}
}

func TestVaultServiceListSecretsDecryptsActiveItemsAndSendsAccessToken(t *testing.T) {
	session := testSession()
	activeMetadata := []byte(`{"title":"active secret"}`)
	activePayload := []byte("active payload")
	deletedMetadata := []byte(`{"title":"deleted secret"}`)
	deletedPayload := []byte("deleted payload")
	deletedAt := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)

	activeItem := encryptedVaultItem(t, session.VaultKey, "active-id", gophkeeperv1.ItemType_ITEM_TYPE_TEXT, activeMetadata, activePayload)
	deletedItem := encryptedVaultItem(t, session.VaultKey, "deleted-id", gophkeeperv1.ItemType_ITEM_TYPE_TEXT, deletedMetadata, deletedPayload)
	deletedItem.SetDeletedAt(timestamppb.New(deletedAt))

	vaultClient := &fakeVaultClient{
		listItemsFunc: func(_ context.Context, req *gophkeeperv1.ListItemsRequest, _ ...grpc.CallOption) (*gophkeeperv1.ListItemsResponse, error) {
			if req.GetIncludeDeleted() {
				t.Fatalf("IncludeDeleted = true, want false for active list")
			}

			return gophkeeperv1.ListItemsResponse_builder{
				Items: []*gophkeeperv1.VaultItem{activeItem, deletedItem},
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	secrets, err := service.ListSecrets(context.Background(), session, ListSecretsInput{})
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}

	if len(vaultClient.listItemsCalls) != 1 {
		t.Fatalf("ListItems() calls = %d, want 1", len(vaultClient.listItemsCalls))
	}

	assertOutgoingBearerToken(vaultClient.listItemsCalls[0].ctx, t, session.AccessToken)

	if len(secrets) != 1 {
		t.Fatalf("secrets length = %d, want 1 active secret", len(secrets))
	}

	if secrets[0].ID != "active-id" {
		t.Fatalf("secret id = %q, want active-id", secrets[0].ID)
	}

	if !bytes.Equal(secrets[0].Metadata, activeMetadata) {
		t.Fatalf("secret metadata does not match active plaintext")
	}

	if !bytes.Equal(secrets[0].Payload, activePayload) {
		t.Fatalf("secret payload does not match active plaintext")
	}
}

func TestVaultServiceListSecretsCanIncludeDeletedItems(t *testing.T) {
	session := testSession()
	deletedAt := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	deletedItem := encryptedVaultItem(t, session.VaultKey, "deleted-id", gophkeeperv1.ItemType_ITEM_TYPE_TEXT, []byte(`{"title":"deleted"}`), []byte("deleted payload"))
	deletedItem.SetDeletedAt(timestamppb.New(deletedAt))

	vaultClient := &fakeVaultClient{
		listItemsFunc: func(_ context.Context, req *gophkeeperv1.ListItemsRequest, _ ...grpc.CallOption) (*gophkeeperv1.ListItemsResponse, error) {
			if !req.GetIncludeDeleted() {
				t.Fatalf("IncludeDeleted = false, want true")
			}

			return gophkeeperv1.ListItemsResponse_builder{
				Items: []*gophkeeperv1.VaultItem{deletedItem},
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	secrets, err := service.ListSecrets(context.Background(), session, ListSecretsInput{IncludeDeleted: true})
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}

	if len(secrets) != 1 {
		t.Fatalf("secrets length = %d, want 1", len(secrets))
	}

	if secrets[0].DeletedAt == nil {
		t.Fatalf("DeletedAt = nil, want deleted timestamp")
	}
}

func TestVaultServiceUpdateSecretEncryptsPayloadAndSendsExpectedVersion(t *testing.T) {
	session := testSession()
	metadataPlaintext := []byte(`{"title":"updated secret"}`)
	payloadPlaintext := []byte("updated payload")

	vaultClient := &fakeVaultClient{
		updateItemFunc: func(_ context.Context, req *gophkeeperv1.UpdateItemRequest, _ ...grpc.CallOption) (*gophkeeperv1.UpdateItemResponse, error) {
			if req.GetId() != "item-id-1" {
				t.Fatalf("request id = %q, want item-id-1", req.GetId())
			}

			if req.GetExpectedVersion() != 3 {
				t.Fatalf("expected version = %d, want 3", req.GetExpectedVersion())
			}

			assertEncryptedDataDecrypts(t, session.VaultKey, req.GetMetadata(), metadataPlaintext)
			assertEncryptedDataDecrypts(t, session.VaultKey, req.GetPayload(), payloadPlaintext)

			return gophkeeperv1.UpdateItemResponse_builder{
				Item: gophkeeperv1.VaultItem_builder{
					Id:                   req.GetId(),
					Type:                 req.GetType(),
					Metadata:             req.GetMetadata(),
					Payload:              req.GetPayload(),
					EncryptionAlg:        req.GetEncryptionAlg(),
					PayloadSchemaVersion: req.GetPayloadSchemaVersion(),
					Version:              4,
				}.Build(),
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	secret, err := service.UpdateSecret(context.Background(), session, UpdateSecretInput{
		ID:                   " item-id-1 ",
		ExpectedVersion:      3,
		Type:                 SecretTypeText,
		Metadata:             metadataPlaintext,
		Payload:              payloadPlaintext,
		PayloadSchemaVersion: 2,
	})
	if err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}

	if len(vaultClient.updateItemCalls) != 1 {
		t.Fatalf("UpdateItem() calls = %d, want 1", len(vaultClient.updateItemCalls))
	}

	assertOutgoingBearerToken(vaultClient.updateItemCalls[0].ctx, t, session.AccessToken)

	if secret.Version != 4 {
		t.Fatalf("secret version = %d, want 4", secret.Version)
	}

	if !bytes.Equal(secret.Payload, payloadPlaintext) {
		t.Fatalf("secret payload does not match updated plaintext")
	}
}

func TestVaultServiceDeleteSecretSendsExpectedVersion(t *testing.T) {
	session := testSession()
	deletedAt := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	vaultClient := &fakeVaultClient{
		deleteItemFunc: func(_ context.Context, req *gophkeeperv1.DeleteItemRequest, _ ...grpc.CallOption) (*gophkeeperv1.DeleteItemResponse, error) {
			if req.GetId() != "item-id-1" {
				t.Fatalf("request id = %q, want item-id-1", req.GetId())
			}

			if req.GetExpectedVersion() != 7 {
				t.Fatalf("expected version = %d, want 7", req.GetExpectedVersion())
			}

			return gophkeeperv1.DeleteItemResponse_builder{
				Id:        req.GetId(),
				Version:   8,
				DeletedAt: timestamppb.New(deletedAt),
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	result, err := service.DeleteSecret(context.Background(), session, DeleteSecretInput{
		ID:              " item-id-1 ",
		ExpectedVersion: 7,
	})
	if err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}

	if len(vaultClient.deleteItemCalls) != 1 {
		t.Fatalf("DeleteItem() calls = %d, want 1", len(vaultClient.deleteItemCalls))
	}

	assertOutgoingBearerToken(vaultClient.deleteItemCalls[0].ctx, t, session.AccessToken)

	if result.ID != "item-id-1" {
		t.Fatalf("result id = %q, want item-id-1", result.ID)
	}

	if result.Version != 8 {
		t.Fatalf("result version = %d, want 8", result.Version)
	}

	if !result.DeletedAt.Equal(deletedAt) {
		t.Fatalf("deleted at = %s, want %s", result.DeletedAt, deletedAt)
	}
}

func TestVaultServiceSyncSecretsDecryptsChangedItemsAndSendsAccessToken(t *testing.T) {
	session := testSession()
	changedAfter := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	nextChangedAfter := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	deletedAt := time.Date(2026, 5, 20, 11, 0, 0, 0, time.UTC)

	activeMetadata := []byte(`{"title":"active note"}`)
	activePayload := []byte("active secret")
	deletedMetadata := []byte(`{"title":"deleted note"}`)
	deletedPayload := []byte("deleted secret")

	activeItem := encryptedVaultItem(t, session.VaultKey, "active-id", gophkeeperv1.ItemType_ITEM_TYPE_TEXT, activeMetadata, activePayload)
	deletedItem := encryptedVaultItem(t, session.VaultKey, "deleted-id", gophkeeperv1.ItemType_ITEM_TYPE_TEXT, deletedMetadata, deletedPayload)
	deletedItem.SetDeletedAt(timestamppb.New(deletedAt))

	vaultClient := &fakeVaultClient{
		syncFunc: func(_ context.Context, req *gophkeeperv1.SyncRequest, _ ...grpc.CallOption) (*gophkeeperv1.SyncResponse, error) {
			if req.GetChangedAfter() == nil {
				t.Fatalf("ChangedAfter = nil, want timestamp")
			}

			if !req.GetChangedAfter().AsTime().Equal(changedAfter) {
				t.Fatalf("ChangedAfter = %s, want %s", req.GetChangedAfter().AsTime(), changedAfter)
			}

			return gophkeeperv1.SyncResponse_builder{
				Items:            []*gophkeeperv1.VaultItem{activeItem, deletedItem},
				NextChangedAfter: timestamppb.New(nextChangedAfter),
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	result, err := service.SyncSecrets(context.Background(), session, SyncSecretsInput{
		ChangedAfter: changedAfter,
	})
	if err != nil {
		t.Fatalf("SyncSecrets() error = %v", err)
	}

	if len(vaultClient.syncCalls) != 1 {
		t.Fatalf("Sync() calls = %d, want 1", len(vaultClient.syncCalls))
	}

	assertOutgoingBearerToken(vaultClient.syncCalls[0].ctx, t, session.AccessToken)

	if len(result.Secrets) != 2 {
		t.Fatalf("secrets length = %d, want 2", len(result.Secrets))
	}

	if result.Secrets[0].ID != "active-id" {
		t.Fatalf("active secret id = %q, want active-id", result.Secrets[0].ID)
	}

	if !bytes.Equal(result.Secrets[0].Payload, activePayload) {
		t.Fatalf("active secret payload does not match plaintext")
	}

	if result.Secrets[1].DeletedAt == nil {
		t.Fatalf("deleted secret DeletedAt = nil")
	}

	if !result.Secrets[1].DeletedAt.Equal(deletedAt) {
		t.Fatalf("deleted secret DeletedAt = %s, want %s", *result.Secrets[1].DeletedAt, deletedAt)
	}

	if !result.NextChangedAfter.Equal(nextChangedAfter) {
		t.Fatalf("NextChangedAfter = %s, want %s", result.NextChangedAfter, nextChangedAfter)
	}
}

func TestVaultServiceGetSecretReturnsErrorWhenCiphertextIsDamaged(t *testing.T) {
	session := testSession()
	encryptedMetadata, err := payload.Encrypt(session.VaultKey, []byte(`{"title":"damaged"}`))
	if err != nil {
		t.Fatalf("encrypt metadata: %v", err)
	}

	encryptedPayload, err := payload.Encrypt(session.VaultKey, []byte("secret payload"))
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	encryptedPayload.Ciphertext[0] ^= 0xff

	vaultClient := &fakeVaultClient{
		getItemFunc: func(context.Context, *gophkeeperv1.GetItemRequest, ...grpc.CallOption) (*gophkeeperv1.GetItemResponse, error) {
			return gophkeeperv1.GetItemResponse_builder{
				Item: gophkeeperv1.VaultItem_builder{
					Id:                   "item-id-1",
					Type:                 gophkeeperv1.ItemType_ITEM_TYPE_TEXT,
					Metadata:             encryptedDataToProto(encryptedMetadata),
					Payload:              encryptedDataToProto(encryptedPayload),
					EncryptionAlg:        payload.EncryptionAlgorithm,
					PayloadSchemaVersion: 1,
				}.Build(),
			}.Build(), nil
		},
	}
	service := NewVaultService(vaultClient)

	_, err = service.GetSecret(context.Background(), session, GetSecretInput{ID: "item-id-1"})
	if err == nil {
		t.Fatalf("GetSecret() error = nil, want error")
	}
}

func TestVaultServiceReturnsErrorForInvalidInputAndDoesNotCallGRPC(t *testing.T) {
	validSession := testSession()

	tests := []struct {
		name    string
		session Session
		create  CreateSecretInput
		get     GetSecretInput
		list    ListSecretsInput
		update  UpdateSecretInput
		delete  DeleteSecretInput
		sync    SyncSecretsInput
		method  string
	}{
		{
			name:    "create without access token",
			session: Session{VaultKey: validSession.VaultKey},
			create: CreateSecretInput{
				Type:                 SecretTypeText,
				Metadata:             []byte("{}"),
				Payload:              []byte("secret"),
				PayloadSchemaVersion: 1,
			},
			method: "create",
		},
		{
			name: "create without vault key",
			session: Session{
				AccessToken: "access-token",
			},
			create: CreateSecretInput{
				Type:                 SecretTypeText,
				Metadata:             []byte("{}"),
				Payload:              []byte("secret"),
				PayloadSchemaVersion: 1,
			},
			method: "create",
		},
		{
			name:    "create without type",
			session: validSession,
			create: CreateSecretInput{
				Metadata:             []byte("{}"),
				Payload:              []byte("secret"),
				PayloadSchemaVersion: 1,
			},
			method: "create",
		},
		{
			name:    "create without payload schema version",
			session: validSession,
			create: CreateSecretInput{
				Type:     SecretTypeText,
				Metadata: []byte("{}"),
				Payload:  []byte("secret"),
			},
			method: "create",
		},
		{
			name:    "get without id",
			session: validSession,
			get:     GetSecretInput{},
			method:  "get",
		},
		{
			name:    "update without id",
			session: validSession,
			update: UpdateSecretInput{
				ExpectedVersion:      1,
				Type:                 SecretTypeText,
				Metadata:             []byte("{}"),
				Payload:              []byte("secret"),
				PayloadSchemaVersion: 1,
			},
			method: "update",
		},
		{
			name:    "update without expected version",
			session: validSession,
			update: UpdateSecretInput{
				ID:                   "item-id-1",
				Type:                 SecretTypeText,
				Metadata:             []byte("{}"),
				Payload:              []byte("secret"),
				PayloadSchemaVersion: 1,
			},
			method: "update",
		},
		{
			name:    "delete without id",
			session: validSession,
			delete: DeleteSecretInput{
				ExpectedVersion: 1,
			},
			method: "delete",
		},
		{
			name:    "delete without expected version",
			session: validSession,
			delete: DeleteSecretInput{
				ID: "item-id-1",
			},
			method: "delete",
		},
		{
			name:    "sync without access token",
			session: Session{VaultKey: validSession.VaultKey},
			sync:    SyncSecretsInput{},
			method:  "sync",
		},
		{
			name: "sync without vault key",
			session: Session{
				AccessToken: "access-token",
			},
			sync:   SyncSecretsInput{},
			method: "sync",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vaultClient := &fakeVaultClient{}
			service := NewVaultService(vaultClient)

			var err error
			switch tt.method {
			case "create":
				_, err = service.CreateSecret(context.Background(), tt.session, tt.create)
			case "get":
				_, err = service.GetSecret(context.Background(), tt.session, tt.get)
			case "list":
				_, err = service.ListSecrets(context.Background(), tt.session, tt.list)
			case "update":
				_, err = service.UpdateSecret(context.Background(), tt.session, tt.update)
			case "delete":
				_, err = service.DeleteSecret(context.Background(), tt.session, tt.delete)
			case "sync":
				_, err = service.SyncSecrets(context.Background(), tt.session, tt.sync)
			default:
				t.Fatalf("unknown method %q", tt.method)
			}
			if err == nil {
				t.Fatalf("%s error = nil, want error", tt.method)
			}

			if len(vaultClient.createItemCalls) != 0 {
				t.Fatalf("CreateItem() calls = %d, want 0", len(vaultClient.createItemCalls))
			}

			if len(vaultClient.getItemCalls) != 0 {
				t.Fatalf("GetItem() calls = %d, want 0", len(vaultClient.getItemCalls))
			}

			if len(vaultClient.listItemsCalls) != 0 {
				t.Fatalf("ListItems() calls = %d, want 0", len(vaultClient.listItemsCalls))
			}

			if len(vaultClient.updateItemCalls) != 0 {
				t.Fatalf("UpdateItem() calls = %d, want 0", len(vaultClient.updateItemCalls))
			}

			if len(vaultClient.deleteItemCalls) != 0 {
				t.Fatalf("DeleteItem() calls = %d, want 0", len(vaultClient.deleteItemCalls))
			}

			if len(vaultClient.syncCalls) != 0 {
				t.Fatalf("Sync() calls = %d, want 0", len(vaultClient.syncCalls))
			}
		})
	}
}

func TestVaultServiceReturnsErrorForMissingClient(t *testing.T) {
	service := NewVaultService(nil)
	session := testSession()

	_, err := service.CreateSecret(context.Background(), session, CreateSecretInput{
		Type:                 SecretTypeText,
		Metadata:             []byte("{}"),
		Payload:              []byte("secret"),
		PayloadSchemaVersion: 1,
	})
	if err == nil {
		t.Fatalf("CreateSecret() error = nil, want error")
	}

	_, err = service.GetSecret(context.Background(), session, GetSecretInput{ID: "item-id-1"})
	if err == nil {
		t.Fatalf("GetSecret() error = nil, want error")
	}

	_, err = service.ListSecrets(context.Background(), session, ListSecretsInput{})
	if err == nil {
		t.Fatalf("ListSecrets() error = nil, want error")
	}

	_, err = service.UpdateSecret(context.Background(), session, UpdateSecretInput{
		ID:                   "item-id-1",
		ExpectedVersion:      1,
		Type:                 SecretTypeText,
		Metadata:             []byte("{}"),
		Payload:              []byte("secret"),
		PayloadSchemaVersion: 1,
	})
	if err == nil {
		t.Fatalf("UpdateSecret() error = nil, want error")
	}

	_, err = service.DeleteSecret(context.Background(), session, DeleteSecretInput{
		ID:              "item-id-1",
		ExpectedVersion: 1,
	})
	if err == nil {
		t.Fatalf("DeleteSecret() error = nil, want error")
	}

	_, err = service.SyncSecrets(context.Background(), session, SyncSecretsInput{})
	if err == nil {
		t.Fatalf("SyncSecrets() error = nil, want error")
	}
}

func testSession() Session {
	return Session{
		AccessToken: "access-token",
		VaultKey:    bytes.Repeat([]byte{1}, vaultkey.KeyLength),
	}
}

func assertOutgoingBearerToken(ctx context.Context, t *testing.T, token string) {
	t.Helper()

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatalf("outgoing metadata is missing")
	}

	values := md.Get("authorization")
	if len(values) != 1 {
		t.Fatalf("authorization metadata values = %d, want 1", len(values))
	}

	want := "Bearer " + token
	if values[0] != want {
		t.Fatalf("authorization metadata = %q, want %q", values[0], want)
	}
}

func assertEncryptedDataDecrypts(t *testing.T, vaultKey []byte, data *gophkeeperv1.EncryptedData, want []byte) {
	t.Helper()

	if data == nil {
		t.Fatalf("encrypted data is nil")
	}

	if len(data.GetCiphertext()) == 0 {
		t.Fatalf("ciphertext is empty")
	}

	if len(data.GetNonce()) != payload.NonceLength {
		t.Fatalf("nonce length = %d, want %d", len(data.GetNonce()), payload.NonceLength)
	}

	plaintext, err := payload.Decrypt(vaultKey, encryptedDataFromProto(data))
	if err != nil {
		t.Fatalf("decrypt encrypted data: %v", err)
	}

	if !bytes.Equal(plaintext, want) {
		t.Fatalf("decrypted data = %q, want %q", plaintext, want)
	}
}

func encryptedVaultItem(t *testing.T, vaultKey []byte, id string, itemType gophkeeperv1.ItemType, metadataPlaintext []byte, payloadPlaintext []byte) *gophkeeperv1.VaultItem {
	t.Helper()

	encryptedMetadata, err := payload.Encrypt(vaultKey, metadataPlaintext)
	if err != nil {
		t.Fatalf("encrypt metadata: %v", err)
	}

	encryptedPayload, err := payload.Encrypt(vaultKey, payloadPlaintext)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	return gophkeeperv1.VaultItem_builder{
		Id:                   id,
		Type:                 itemType,
		Metadata:             encryptedDataToProto(encryptedMetadata),
		Payload:              encryptedDataToProto(encryptedPayload),
		EncryptionAlg:        payload.EncryptionAlgorithm,
		PayloadSchemaVersion: 1,
		Version:              1,
	}.Build()
}
