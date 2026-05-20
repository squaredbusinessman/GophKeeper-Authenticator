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

	created, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeText,
		Metadata:             metadata,
		Payload:              textPayload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}

	if created.ID == "" {
		t.Fatalf("created secret id is empty")
	}

	listed, err := vaultService.ListSecrets(ctx, session, core.ListSecretsInput{})
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}

	if len(listed) != 1 {
		t.Fatalf("listed secrets = %d, want 1", len(listed))
	}

	if listed[0].ID != created.ID {
		t.Fatalf("listed id = %q, want %q", listed[0].ID, created.ID)
	}

	got, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: created.ID})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}

	decodedText, err := core.DecodeTextPayload(got.Payload, got.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("decode text payload: %v", err)
	}

	if decodedText.Text != "smoke secret" {
		t.Fatalf("payload text = %q, want smoke secret", decodedText.Text)
	}

	updatedPayload, updatedSchemaVersion, err := core.EncodeTextPayload(core.TextPayload{Text: "updated smoke secret"})
	if err != nil {
		t.Fatalf("encode updated text payload: %v", err)
	}

	updated, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   created.ID,
		ExpectedVersion:      got.Version,
		Type:                 core.SecretTypeText,
		Metadata:             []byte(`{"title":"updated smoke note"}`),
		Payload:              updatedPayload,
		PayloadSchemaVersion: updatedSchemaVersion,
	})
	if err != nil {
		t.Fatalf("update secret: %v", err)
	}

	if updated.Version != got.Version+1 {
		t.Fatalf("updated version = %d, want %d", updated.Version, got.Version+1)
	}

	deleted, err := vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
		ID:              created.ID,
		ExpectedVersion: updated.Version,
	})
	if err != nil {
		t.Fatalf("delete secret: %v", err)
	}

	if deleted.ID != created.ID {
		t.Fatalf("deleted id = %q, want %q", deleted.ID, created.ID)
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

	var foundDeleted bool
	for _, secret := range synced.Secrets {
		if secret.ID == created.ID && secret.DeletedAt != nil {
			foundDeleted = true
			break
		}
	}

	if !foundDeleted {
		t.Fatalf("sync did not return deleted tombstone for %s", created.ID)
	}
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
