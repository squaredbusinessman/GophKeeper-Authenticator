//go:build smoke

package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	serverblob "github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/blob"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/database"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/migrations"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestSmokeAuthVaultAndSyncFlow(t *testing.T) {
	dsn := getenv("GOPHKEEPER_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("GOPHKEEPER_TEST_DATABASE_DSN is required for smoke test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db := openSmokeDatabase(t, ctx, dsn)

	if err := migrations.Up(ctx, db, filepath.Join(repoRoot(t), "migrations")); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	address := freeTCPAddress(t)
	startSmokeServer(t, db, dsn, address)

	conn := connectSmokeClient(t, ctx, address)
	defer conn.Close()

	authService := core.NewAuthService(
		gophkeeperv1.NewAuthServiceClient(conn),
		core.NewFileTokenStore(filepath.Join(t.TempDir(), "token.json")),
	)
	vaultService := core.NewVaultService(gophkeeperv1.NewVaultServiceClient(conn))
	blobService := core.NewBlobService(gophkeeperv1.NewBlobServiceClient(conn))

	login := fmt.Sprintf("smoke-%d@example.com", time.Now().UnixNano())
	loginPassword := "login-password-123"
	masterPassword := "master-password-123"

	registeredSession, err := authService.Register(ctx, core.RegisterInput{
		Login:          login,
		LoginPassword:  loginPassword,
		MasterPassword: masterPassword,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if registeredSession.AccessToken == "" {
		t.Fatalf("registered access token is empty")
	}

	session, err := authService.Login(ctx, core.LoginInput{
		Login:          login,
		LoginPassword:  loginPassword,
		MasterPassword: masterPassword,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if !bytes.Equal(session.VaultKey, registeredSession.VaultKey) {
		t.Fatalf("login vault key does not match registered vault key")
	}

	metadata := []byte(`{"title":"smoke note"}`)
	textPayload, schemaVersion, err := core.EncodeTextPayload(core.TextPayload{Text: "smoke secret"})
	if err != nil {
		t.Fatalf("encode text payload: %v", err)
	}

	createdText, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeText,
		Metadata:             metadata,
		Payload:              textPayload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		t.Fatalf("create text secret: %v", err)
	}

	if createdText.ID == "" {
		t.Fatalf("created text secret id is empty")
	}

	loginPasswordPayload, loginPasswordSchemaVersion, err := core.EncodeLoginPasswordPayload(core.LoginPasswordPayload{
		Login:    "smoke-login",
		Password: "smoke-password",
		URL:      "https://example.com",
		Notes:    "smoke credentials",
	})
	if err != nil {
		t.Fatalf("encode login/password payload: %v", err)
	}

	createdLoginPassword, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeLoginPassword,
		Metadata:             []byte(`{"title":"smoke login password"}`),
		Payload:              loginPasswordPayload,
		PayloadSchemaVersion: loginPasswordSchemaVersion,
	})
	if err != nil {
		t.Fatalf("create login/password secret: %v", err)
	}

	bankCardPayload, bankCardSchemaVersion, err := core.EncodeBankCardPayload(core.BankCardPayload{
		Number:          "4111111111111111",
		CardholderName:  "SMOKE USER",
		ExpirationMonth: "05",
		ExpirationYear:  "2030",
		CVV:             "123",
		Notes:           "smoke card",
	})
	if err != nil {
		t.Fatalf("encode bank card payload: %v", err)
	}

	createdBankCard, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeBankCard,
		Metadata:             []byte(`{"title":"smoke bank card"}`),
		Payload:              bankCardPayload,
		PayloadSchemaVersion: bankCardSchemaVersion,
	})
	if err != nil {
		t.Fatalf("create bank card secret: %v", err)
	}

	binaryPayload, err := blobService.UploadBinary(ctx, session, core.UploadBinaryInput{
		FileName:    "smoke.bin",
		ContentType: "application/octet-stream",
		Data:        []byte{0x01, 0x02, 0x03},
	})
	if err != nil {
		t.Fatalf("upload binary blob: %v", err)
	}
	binaryPayloadBytes, binarySchemaVersion, err := core.EncodeBinaryPayload(binaryPayload)
	if err != nil {
		t.Fatalf("encode binary payload metadata: %v", err)
	}

	createdBinary, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeBinary,
		Metadata:             []byte(`{"title":"smoke binary"}`),
		Payload:              binaryPayloadBytes,
		PayloadSchemaVersion: binarySchemaVersion,
	})
	if err != nil {
		t.Fatalf("create binary secret: %v", err)
	}

	otpPayload, otpSchemaVersion, err := core.EncodeOTPPayload(core.OTPPayload{
		Issuer:        "Smoke",
		AccountName:   login,
		Secret:        "JBSWY3DPEHPK3PXP",
		Algorithm:     "SHA1",
		Digits:        6,
		PeriodSeconds: 30,
		Notes:         "smoke otp",
	})
	if err != nil {
		t.Fatalf("encode otp payload: %v", err)
	}

	createdOTP, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeOTP,
		Metadata:             []byte(`{"title":"smoke otp"}`),
		Payload:              otpPayload,
		PayloadSchemaVersion: otpSchemaVersion,
	})
	if err != nil {
		t.Fatalf("create otp secret: %v", err)
	}

	listed, err := vaultService.ListSecrets(ctx, session, core.ListSecretsInput{})
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}

	if len(listed) != 5 {
		t.Fatalf("listed secrets = %d, want 5", len(listed))
	}

	assertSmokeListContains(t, listed, createdText.ID)
	assertSmokeListContains(t, listed, createdLoginPassword.ID)
	assertSmokeListContains(t, listed, createdBankCard.ID)
	assertSmokeListContains(t, listed, createdBinary.ID)
	assertSmokeListContains(t, listed, createdOTP.ID)

	gotText, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdText.ID})
	if err != nil {
		t.Fatalf("get text secret: %v", err)
	}

	decodedText, err := core.DecodeTextPayload(gotText.Payload, gotText.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode text payload: %v", err)
	}

	if decodedText.Text != "smoke secret" {
		t.Fatalf("payload text = %q, want smoke secret", decodedText.Text)
	}

	gotLoginPassword, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdLoginPassword.ID})
	if err != nil {
		t.Fatalf("get login/password secret: %v", err)
	}

	decodedLoginPassword, err := core.DecodeLoginPasswordPayload(gotLoginPassword.Payload, gotLoginPassword.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode login/password payload: %v", err)
	}

	if decodedLoginPassword.Login != "smoke-login" || decodedLoginPassword.Password != "smoke-password" {
		t.Fatalf("decoded login/password = %+v, want smoke credentials", decodedLoginPassword)
	}

	gotBankCard, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdBankCard.ID})
	if err != nil {
		t.Fatalf("get bank card secret: %v", err)
	}

	decodedBankCard, err := core.DecodeBankCardPayload(gotBankCard.Payload, gotBankCard.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode bank card payload: %v", err)
	}

	if decodedBankCard.Number != "4111111111111111" || decodedBankCard.CardholderName != "SMOKE USER" {
		t.Fatalf("decoded bank card = %+v, want smoke bank card", decodedBankCard)
	}

	gotBinary, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdBinary.ID})
	if err != nil {
		t.Fatalf("get binary secret: %v", err)
	}

	decodedBinary, err := core.DecodeBinaryPayload(gotBinary.Payload, gotBinary.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode binary payload: %v", err)
	}

	if decodedBinary.FileName != "smoke.bin" || decodedBinary.BlobID == "" {
		t.Fatalf("decoded binary metadata = %+v, want smoke binary metadata", decodedBinary)
	}
	downloadedBinary, err := blobService.DownloadBinary(ctx, session, core.DownloadBinaryInput{Payload: decodedBinary})
	if err != nil {
		t.Fatalf("download binary blob: %v", err)
	}
	if !bytes.Equal(downloadedBinary, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("downloaded binary = %v, want smoke binary bytes", downloadedBinary)
	}

	gotOTP, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdOTP.ID})
	if err != nil {
		t.Fatalf("get otp secret: %v", err)
	}

	decodedOTP, err := core.DecodeOTPPayload(gotOTP.Payload, gotOTP.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode otp payload: %v", err)
	}

	if decodedOTP.Secret != "JBSWY3DPEHPK3PXP" || decodedOTP.AccountName != login {
		t.Fatalf("decoded otp = %+v, want smoke otp", decodedOTP)
	}

	otpCode, err := core.CurrentOTPCode(decodedOTP, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("calculate otp code: %v", err)
	}

	if otpCode.Value == "" {
		t.Fatalf("otp code is empty")
	}

	updatedTextPayload, updatedTextSchemaVersion, err := core.EncodeTextPayload(core.TextPayload{Text: "updated smoke secret"})
	if err != nil {
		t.Fatalf("encode updated text payload: %v", err)
	}

	updatedText, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   createdText.ID,
		ExpectedVersion:      gotText.Version,
		Type:                 core.SecretTypeText,
		Metadata:             []byte(`{"title":"updated smoke note"}`),
		Payload:              updatedTextPayload,
		PayloadSchemaVersion: updatedTextSchemaVersion,
	})
	if err != nil {
		t.Fatalf("update text secret: %v", err)
	}

	if updatedText.Version != gotText.Version+1 {
		t.Fatalf("updated text version = %d, want %d", updatedText.Version, gotText.Version+1)
	}

	updatedLoginPasswordPayload, updatedLoginPasswordSchemaVersion, err := core.EncodeLoginPasswordPayload(core.LoginPasswordPayload{
		Login:    "updated-smoke-login",
		Password: "updated-smoke-password",
		URL:      "https://updated.example.com",
		Notes:    "updated smoke credentials",
	})
	if err != nil {
		t.Fatalf("encode updated login/password payload: %v", err)
	}

	updatedLoginPassword, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   createdLoginPassword.ID,
		ExpectedVersion:      gotLoginPassword.Version,
		Type:                 core.SecretTypeLoginPassword,
		Metadata:             []byte(`{"title":"updated smoke login password"}`),
		Payload:              updatedLoginPasswordPayload,
		PayloadSchemaVersion: updatedLoginPasswordSchemaVersion,
	})
	if err != nil {
		t.Fatalf("update login/password secret: %v", err)
	}

	if updatedLoginPassword.Version != gotLoginPassword.Version+1 {
		t.Fatalf("updated login/password version = %d, want %d", updatedLoginPassword.Version, gotLoginPassword.Version+1)
	}

	updatedBankCardPayload, updatedBankCardSchemaVersion, err := core.EncodeBankCardPayload(core.BankCardPayload{
		Number:          "5555555555554444",
		CardholderName:  "UPDATED SMOKE USER",
		ExpirationMonth: "06",
		ExpirationYear:  "2031",
		CVV:             "321",
		Notes:           "updated smoke card",
	})
	if err != nil {
		t.Fatalf("encode updated bank card payload: %v", err)
	}

	updatedBankCard, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   createdBankCard.ID,
		ExpectedVersion:      gotBankCard.Version,
		Type:                 core.SecretTypeBankCard,
		Metadata:             []byte(`{"title":"updated smoke bank card"}`),
		Payload:              updatedBankCardPayload,
		PayloadSchemaVersion: updatedBankCardSchemaVersion,
	})
	if err != nil {
		t.Fatalf("update bank card secret: %v", err)
	}

	if updatedBankCard.Version != gotBankCard.Version+1 {
		t.Fatalf("updated bank card version = %d, want %d", updatedBankCard.Version, gotBankCard.Version+1)
	}

	updatedBinaryPayload, err := blobService.UploadBinary(ctx, session, core.UploadBinaryInput{
		FileName:    "updated-smoke.bin",
		ContentType: "application/octet-stream",
		Data:        []byte{0x04, 0x05, 0x06},
	})
	if err != nil {
		t.Fatalf("upload updated binary blob: %v", err)
	}
	updatedBinaryPayloadBytes, updatedBinarySchemaVersion, err := core.EncodeBinaryPayload(updatedBinaryPayload)
	if err != nil {
		t.Fatalf("encode updated binary payload metadata: %v", err)
	}

	updatedBinary, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   createdBinary.ID,
		ExpectedVersion:      gotBinary.Version,
		Type:                 core.SecretTypeBinary,
		Metadata:             []byte(`{"title":"updated smoke binary"}`),
		Payload:              updatedBinaryPayloadBytes,
		PayloadSchemaVersion: updatedBinarySchemaVersion,
	})
	if err != nil {
		t.Fatalf("update binary secret: %v", err)
	}

	if updatedBinary.Version != gotBinary.Version+1 {
		t.Fatalf("updated binary version = %d, want %d", updatedBinary.Version, gotBinary.Version+1)
	}

	gotUpdatedText, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdText.ID})
	if err != nil {
		t.Fatalf("get updated text secret: %v", err)
	}

	decodedUpdatedText, err := core.DecodeTextPayload(gotUpdatedText.Payload, gotUpdatedText.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode updated text payload: %v", err)
	}

	if decodedUpdatedText.Text != "updated smoke secret" {
		t.Fatalf("updated text = %q, want updated smoke secret", decodedUpdatedText.Text)
	}

	gotUpdatedLoginPassword, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdLoginPassword.ID})
	if err != nil {
		t.Fatalf("get updated login/password secret: %v", err)
	}

	decodedUpdatedLoginPassword, err := core.DecodeLoginPasswordPayload(gotUpdatedLoginPassword.Payload, gotUpdatedLoginPassword.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode updated login/password payload: %v", err)
	}

	if decodedUpdatedLoginPassword.Login != "updated-smoke-login" || decodedUpdatedLoginPassword.Password != "updated-smoke-password" {
		t.Fatalf("updated login/password = %+v, want updated smoke credentials", decodedUpdatedLoginPassword)
	}

	gotUpdatedBankCard, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdBankCard.ID})
	if err != nil {
		t.Fatalf("get updated bank card secret: %v", err)
	}

	decodedUpdatedBankCard, err := core.DecodeBankCardPayload(gotUpdatedBankCard.Payload, gotUpdatedBankCard.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode updated bank card payload: %v", err)
	}

	if decodedUpdatedBankCard.Number != "5555555555554444" || decodedUpdatedBankCard.CardholderName != "UPDATED SMOKE USER" {
		t.Fatalf("updated bank card = %+v, want updated smoke bank card", decodedUpdatedBankCard)
	}

	gotUpdatedBinary, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: createdBinary.ID})
	if err != nil {
		t.Fatalf("get updated binary secret: %v", err)
	}

	decodedUpdatedBinary, err := core.DecodeBinaryPayload(gotUpdatedBinary.Payload, gotUpdatedBinary.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode updated binary payload: %v", err)
	}

	if decodedUpdatedBinary.FileName != "updated-smoke.bin" || decodedUpdatedBinary.BlobID == "" {
		t.Fatalf("updated binary metadata = %+v, want updated smoke binary metadata", decodedUpdatedBinary)
	}
	downloadedUpdatedBinary, err := blobService.DownloadBinary(ctx, session, core.DownloadBinaryInput{Payload: decodedUpdatedBinary})
	if err != nil {
		t.Fatalf("download updated binary blob: %v", err)
	}
	if !bytes.Equal(downloadedUpdatedBinary, []byte{0x04, 0x05, 0x06}) {
		t.Fatalf("downloaded updated binary = %v, want updated smoke binary bytes", downloadedUpdatedBinary)
	}

	deletedText, err := vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
		ID:              createdText.ID,
		ExpectedVersion: updatedText.Version,
	})
	if err != nil {
		t.Fatalf("delete text secret: %v", err)
	}

	if deletedText.ID != createdText.ID {
		t.Fatalf("deleted text id = %q, want %q", deletedText.ID, createdText.ID)
	}

	deletedLoginPassword, err := vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
		ID:              createdLoginPassword.ID,
		ExpectedVersion: updatedLoginPassword.Version,
	})
	if err != nil {
		t.Fatalf("delete login/password secret: %v", err)
	}

	if deletedLoginPassword.ID != createdLoginPassword.ID {
		t.Fatalf("deleted login/password id = %q, want %q", deletedLoginPassword.ID, createdLoginPassword.ID)
	}

	deletedBankCard, err := vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
		ID:              createdBankCard.ID,
		ExpectedVersion: updatedBankCard.Version,
	})
	if err != nil {
		t.Fatalf("delete bank card secret: %v", err)
	}

	if deletedBankCard.ID != createdBankCard.ID {
		t.Fatalf("deleted bank card id = %q, want %q", deletedBankCard.ID, createdBankCard.ID)
	}

	deletedBinary, err := vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
		ID:              createdBinary.ID,
		ExpectedVersion: updatedBinary.Version,
	})
	if err != nil {
		t.Fatalf("delete binary secret: %v", err)
	}

	if deletedBinary.ID != createdBinary.ID {
		t.Fatalf("deleted binary id = %q, want %q", deletedBinary.ID, createdBinary.ID)
	}

	deletedOTP, err := vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
		ID:              createdOTP.ID,
		ExpectedVersion: gotOTP.Version,
	})
	if err != nil {
		t.Fatalf("delete otp secret: %v", err)
	}

	if deletedOTP.ID != createdOTP.ID {
		t.Fatalf("deleted otp id = %q, want %q", deletedOTP.ID, createdOTP.ID)
	}

	activeAfterDelete, err := vaultService.ListSecrets(ctx, session, core.ListSecretsInput{})
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}

	if len(activeAfterDelete) != 0 {
		t.Fatalf("active secrets after delete = %d, want 0", len(activeAfterDelete))
	}

	synced, err := vaultService.SyncSecrets(ctx, session, core.SyncSecretsInput{})
	if err != nil {
		t.Fatalf("sync secrets: %v", err)
	}

	assertSmokeTombstoneContains(t, synced.Secrets, createdText.ID)
	assertSmokeTombstoneContains(t, synced.Secrets, createdLoginPassword.ID)
	assertSmokeTombstoneContains(t, synced.Secrets, createdBankCard.ID)
	assertSmokeTombstoneContains(t, synced.Secrets, createdBinary.ID)
	assertSmokeTombstoneContains(t, synced.Secrets, createdOTP.ID)
}

func assertSmokeListContains(t *testing.T, secrets []core.Secret, id string) {
	t.Helper()

	for _, secret := range secrets {
		if secret.ID == id {
			return
		}
	}

	t.Fatalf("listed secrets do not contain %s", id)
}

func assertSmokeTombstoneContains(t *testing.T, secrets []core.Secret, id string) {
	t.Helper()

	for _, secret := range secrets {
		if secret.ID == id && secret.DeletedAt != nil {
			return
		}
	}

	t.Fatalf("synced secrets do not contain deleted tombstone for %s", id)
}

func openSmokeDatabase(t *testing.T, ctx context.Context, dsn string) *sql.DB {
	t.Helper()

	db, err := database.Open(ctx, &config.Config{
		DatabaseDSN:     dsn,
		DatabasePingTTL: 5 * time.Second,
		GRPCAddress:     "127.0.0.1:0",
		AccessTokenTTL:  5 * time.Minute,
		LogMode:         "prod",
	})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	return db
}

func startSmokeServer(t *testing.T, db *sql.DB, dsn string, address string) *grpcserver.Server {
	t.Helper()

	server, err := grpcserver.New(&config.Config{
		GRPCAddress:        address,
		DatabaseDSN:        dsn,
		DatabasePingTTL:    5 * time.Second,
		AccessTokenSecret:  "smoke-local-secret-32-bytes-value",
		AccessTokenTTL:     5 * time.Minute,
		LogMode:            "prod",
		BlobStorageEnabled: true,
		MinIOBucket:        "smoke-blobs",
		BlobUploadTTL:      time.Hour,
		BlobChunkSize:      4 * 1024 * 1024,
		BlobMaxSize:        32 * 1024 * 1024,
	}, zap.NewNop(), db, newSmokeObjectStore())
	if err != nil {
		t.Fatalf("create grpc server: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	t.Cleanup(func() {
		server.Stop()
		if err := <-errCh; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("grpc server stopped with error: %v", err)
		}
	})

	return server
}

type smokeObjectStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newSmokeObjectStore() *smokeObjectStore {
	return &smokeObjectStore{
		objects: map[string][]byte{},
	}
}

func (s *smokeObjectStore) EnsureBucket(context.Context) error {
	return nil
}

func (s *smokeObjectStore) PutObject(_ context.Context, input serverblob.PutObjectInput) error {
	if strings.TrimSpace(input.Key) == "" {
		return fmt.Errorf("object key is required")
	}
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return err
	}
	if int64(len(data)) != input.Size {
		return fmt.Errorf("object size = %d, want %d", len(data), input.Size)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[input.Key] = append([]byte(nil), data...)
	return nil
}

func (s *smokeObjectStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[key]
	if !ok {
		return nil, fmt.Errorf("object not found")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *smokeObjectStore) StatObject(_ context.Context, key string) (serverblob.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[key]
	if !ok {
		return serverblob.ObjectInfo{}, fmt.Errorf("object not found")
	}
	return serverblob.ObjectInfo{Key: key, Size: int64(len(data))}, nil
}

func (s *smokeObjectStore) RemoveObject(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, key)
	return nil
}

func connectSmokeClient(t *testing.T, ctx context.Context, address string) *grpc.ClientConn {
	t.Helper()

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create grpc client: %v", err)
	}

	authClient := gophkeeperv1.NewAuthServiceClient(conn)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, err = authClient.Login(ctx, &gophkeeperv1.LoginRequest{
			Login:         "smoke-healthcheck@example.com",
			LoginPassword: "wrong-password",
		})
		if status.Code(err) == codes.Unauthenticated {
			return conn
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("grpc server did not become ready")
	return nil
}

func freeTCPAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate tcp port: %v", err)
	}
	defer listener.Close()

	return listener.Addr().String()
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("detect current file")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func getenv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
