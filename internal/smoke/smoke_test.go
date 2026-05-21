//go:build smoke

package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
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

	binaryPayload, binarySchemaVersion, err := core.EncodeBinaryPayload(core.BinaryPayload{
		FileName:    "smoke.bin",
		ContentType: "application/octet-stream",
		Data:        []byte{0x01, 0x02, 0x03},
	})
	if err != nil {
		t.Fatalf("encode binary payload: %v", err)
	}

	createdBinary, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeBinary,
		Metadata:             []byte(`{"title":"smoke binary"}`),
		Payload:              binaryPayload,
		PayloadSchemaVersion: binarySchemaVersion,
	})
	if err != nil {
		t.Fatalf("create binary secret: %v", err)
	}

	listed, err := vaultService.ListSecrets(ctx, session, core.ListSecretsInput{})
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}

	if len(listed) != 4 {
		t.Fatalf("listed secrets = %d, want 4", len(listed))
	}

	assertSmokeListContains(t, listed, createdText.ID)
	assertSmokeListContains(t, listed, createdLoginPassword.ID)
	assertSmokeListContains(t, listed, createdBankCard.ID)
	assertSmokeListContains(t, listed, createdBinary.ID)

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

	if decodedBinary.FileName != "smoke.bin" || !bytes.Equal(decodedBinary.Data, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("decoded binary = %+v, want smoke binary", decodedBinary)
	}

	updatedPayload, updatedSchemaVersion, err := core.EncodeTextPayload(core.TextPayload{Text: "updated smoke secret"})
	if err != nil {
		t.Fatalf("encode updated text payload: %v", err)
	}

	updated, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   createdText.ID,
		ExpectedVersion:      gotText.Version,
		Type:                 core.SecretTypeText,
		Metadata:             []byte(`{"title":"updated smoke note"}`),
		Payload:              updatedPayload,
		PayloadSchemaVersion: updatedSchemaVersion,
	})
	if err != nil {
		t.Fatalf("update secret: %v", err)
	}

	if updated.Version != gotText.Version+1 {
		t.Fatalf("updated version = %d, want %d", updated.Version, gotText.Version+1)
	}

	deleted, err := vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
		ID:              createdText.ID,
		ExpectedVersion: updated.Version,
	})
	if err != nil {
		t.Fatalf("delete secret: %v", err)
	}

	if deleted.ID != createdText.ID {
		t.Fatalf("deleted id = %q, want %q", deleted.ID, createdText.ID)
	}

	activeAfterDelete, err := vaultService.ListSecrets(ctx, session, core.ListSecretsInput{})
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}

	if len(activeAfterDelete) != 3 {
		t.Fatalf("active secrets after delete = %d, want 3", len(activeAfterDelete))
	}

	synced, err := vaultService.SyncSecrets(ctx, session, core.SyncSecretsInput{})
	if err != nil {
		t.Fatalf("sync secrets: %v", err)
	}

	var foundDeleted bool
	for _, secret := range synced.Secrets {
		if secret.ID == createdText.ID && secret.DeletedAt != nil {
			foundDeleted = true
			break
		}
	}

	if !foundDeleted {
		t.Fatalf("sync did not return deleted tombstone for %s", createdText.ID)
	}
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
		GRPCAddress:       address,
		DatabaseDSN:       dsn,
		DatabasePingTTL:   5 * time.Second,
		AccessTokenSecret: "smoke-local-secret",
		AccessTokenTTL:    5 * time.Minute,
		LogMode:           "prod",
	}, zap.NewNop(), db)
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
