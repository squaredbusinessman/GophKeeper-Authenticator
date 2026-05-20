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

	createItemCalls []vaultClientCall[*gophkeeperv1.CreateItemRequest]
	getItemCalls    []vaultClientCall[*gophkeeperv1.GetItemRequest]
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

			return &gophkeeperv1.CreateItemResponse{
				Item: &gophkeeperv1.VaultItem{
					Id:                   "item-id-1",
					Type:                 req.GetType(),
					Metadata:             req.GetMetadata(),
					Payload:              req.GetPayload(),
					EncryptionAlg:        req.GetEncryptionAlg(),
					PayloadSchemaVersion: req.GetPayloadSchemaVersion(),
					Version:              1,
					CreatedAt:            timestamppb.New(createdAt),
					UpdatedAt:            timestamppb.New(updatedAt),
				},
			}, nil
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
	assertOutgoingBearerToken(t, call.ctx, session.AccessToken)

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

			return &gophkeeperv1.GetItemResponse{
				Item: &gophkeeperv1.VaultItem{
					Id:                   "item-id-1",
					Type:                 gophkeeperv1.ItemType_ITEM_TYPE_TEXT,
					Metadata:             encryptedDataToProto(encryptedMetadata),
					Payload:              encryptedDataToProto(encryptedPayload),
					EncryptionAlg:        payload.EncryptionAlgorithm,
					PayloadSchemaVersion: 1,
					Version:              3,
				},
			}, nil
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

	assertOutgoingBearerToken(t, vaultClient.getItemCalls[0].ctx, session.AccessToken)

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
			return &gophkeeperv1.GetItemResponse{
				Item: &gophkeeperv1.VaultItem{
					Id:                   "item-id-1",
					Type:                 gophkeeperv1.ItemType_ITEM_TYPE_TEXT,
					Metadata:             encryptedDataToProto(encryptedMetadata),
					Payload:              encryptedDataToProto(encryptedPayload),
					EncryptionAlg:        payload.EncryptionAlgorithm,
					PayloadSchemaVersion: 1,
				},
			}, nil
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
}

func testSession() Session {
	return Session{
		AccessToken: "access-token",
		VaultKey:    bytes.Repeat([]byte{1}, vaultkey.KeyLength),
	}
}

func assertOutgoingBearerToken(t *testing.T, ctx context.Context, token string) {
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
