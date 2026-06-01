package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/config"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	serverconfig "github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewRuntimeBuildsSharedClientDependencies(t *testing.T) {
	certFile, _ := writeRuntimeTestCertificate(t)
	runtime, err := NewRuntime(&config.Config{
		ServerAddress:     "localhost:9090",
		ServerTLSCertFile: certFile,
		TokenFile:         filepath.Join(t.TempDir(), "token.json"),
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()

	if runtime.Conn == nil {
		t.Fatalf("Conn = nil")
	}

	if runtime.AuthClient == nil {
		t.Fatalf("AuthClient = nil")
	}

	if runtime.VaultClient == nil {
		t.Fatalf("VaultClient = nil")
	}

	if runtime.TokenStore == nil {
		t.Fatalf("TokenStore = nil")
	}

	if runtime.AuthService == nil {
		t.Fatalf("AuthService = nil")
	}

	if runtime.VaultService == nil {
		t.Fatalf("VaultService = nil")
	}
}

func TestNewRuntimeReturnsTLSCredentialError(t *testing.T) {
	_, err := NewRuntime(&config.Config{
		ServerAddress:     "localhost:9090",
		ServerTLSCertFile: filepath.Join(t.TempDir(), "missing.crt"),
		TokenFile:         filepath.Join(t.TempDir(), "token.json"),
	})
	if err == nil {
		t.Fatalf("NewRuntime() error = nil, want error")
	}

	if !errors.Is(err, ErrServerTLSCredentials) {
		t.Fatalf("NewRuntime() error = %q, want TLS credentials", err.Error())
	}
}

func TestNewRuntimeConnectsToTLSServer(t *testing.T) {
	certFile, keyFile := writeRuntimeTestCertificate(t)
	address := runtimeFreeTCPAddress(t)
	server, err := grpcserver.New(&serverconfig.Config{
		GRPCAddress:       address,
		GRPCTLSCertFile:   certFile,
		GRPCTLSKeyFile:    keyFile,
		AccessTokenSecret: "test-access-token-secret-32-bytes",
		AccessTokenTTL:    time.Minute,
	}, zap.NewNop(), nil, nil)
	if err != nil {
		t.Fatalf("grpcserver.New() error = %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Start()
	}()
	t.Cleanup(func() {
		server.Stop()
		if err := <-serveErr; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("server stopped with error: %v", err)
		}
	})

	runtime, err := NewRuntime(&config.Config{
		ServerAddress:     address,
		ServerTLSCertFile: certFile,
		TokenFile:         filepath.Join(t.TempDir(), "token.json"),
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = runtime.VaultClient.ListItems(ctx, gophkeeperv1.ListItemsRequest_builder{}.Build())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want %s, err = %v", status.Code(err), codes.Unauthenticated, err)
	}
}

func TestLoadRuntimeLoadsConfigFromEnv(t *testing.T) {
	certFile, _ := writeRuntimeTestCertificate(t)
	tokenFile := filepath.Join(t.TempDir(), "token.json")
	t.Setenv("GOPHKEEPER_SERVER_ADDRESS", "localhost:9090")
	t.Setenv("GOPHKEEPER_SERVER_TLS_CERT_FILE", certFile)
	t.Setenv("GOPHKEEPER_TOKEN_FILE", tokenFile)

	runtime, err := LoadRuntime()
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	defer runtime.Close()

	if runtime.Config.TokenFile != tokenFile {
		t.Fatalf("TokenFile = %q, want %q", runtime.Config.TokenFile, tokenFile)
	}
}

func TestLoadRuntimeWrapsConfigError(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_ADDRESS", " ")
	t.Setenv("GOPHKEEPER_TOKEN_FILE", filepath.Join(t.TempDir(), "token.json"))

	_, err := LoadRuntime()
	if err == nil {
		t.Fatalf("LoadRuntime() error = nil, want error")
	}

	if !errors.Is(err, ErrClientConfig) {
		t.Fatalf("LoadRuntime() error = %q, want error loading config", err.Error())
	}
}

func TestRuntimeCloseAllowsNilReceiver(t *testing.T) {
	var runtime *Runtime
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewRuntimeRejectsNilConfig(t *testing.T) {
	_, err := NewRuntime(nil)
	if err == nil {
		t.Fatalf("NewRuntime() error = nil, want error")
	}
}

func TestNewRuntimeValidatesConfig(t *testing.T) {
	_, err := NewRuntime(&config.Config{
		ServerAddress: " ",
		TokenFile:     filepath.Join(t.TempDir(), "token.json"),
	})
	if err == nil {
		t.Fatalf("NewRuntime() error = nil, want error")
	}

	if !errors.Is(err, ErrClientConfig) {
		t.Fatalf("NewRuntime() error = %q, want validate client config", err.Error())
	}
}

func TestLoadRuntimeUsesDefaultTokenFile(t *testing.T) {
	certFile, _ := writeRuntimeTestCertificate(t)
	t.Setenv("GOPHKEEPER_SERVER_ADDRESS", "localhost:9090")
	t.Setenv("GOPHKEEPER_SERVER_TLS_CERT_FILE", certFile)
	t.Setenv("GOPHKEEPER_TOKEN_FILE", "")

	runtime, err := LoadRuntime()
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	defer runtime.Close()

	if strings.TrimSpace(runtime.Config.TokenFile) == "" {
		t.Fatalf("TokenFile is empty")
	}

	if !strings.HasSuffix(runtime.Config.TokenFile, filepath.Join(".gophkeeper", "token.json")) {
		t.Fatalf("TokenFile = %q, want default token path", runtime.Config.TokenFile)
	}
}

func writeRuntimeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err = os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile() cert error = %v", err)
	}

	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	if err = os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile() key error = %v", err)
	}

	return certFile, keyFile
}

func runtimeFreeTCPAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	return listener.Addr().String()
}
