package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/config"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestNewStartsServerWithTLSCredentials(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	cfg := &config.Config{
		GRPCAddress:       "127.0.0.1:0",
		GRPCTLSEnabled:    true,
		GRPCTLSCertFile:   certFile,
		GRPCTLSKeyFile:    keyFile,
		AccessTokenSecret: "test-access-token-secret-32-bytes",
		AccessTokenTTL:    time.Minute,
	}

	server, err := New(cfg, zap.NewNop(), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Start()
	}()

	t.Cleanup(func() {
		server.Stop()
		if err := <-serveErr; err != nil {
			t.Logf("server stopped with error: %v", err)
		}
	})

	creds, err := credentials.NewClientTLSFromFile(certFile, "")
	if err != nil {
		t.Fatalf("NewClientTLSFromFile() error = %v", err)
	}

	conn, err := grpc.NewClient(
		server.listener.Addr().String(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	defer conn.Close()

	client := gophkeeperv1.NewVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = client.ListItems(ctx, &gophkeeperv1.ListItemsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want %s, err = %v", status.Code(err), codes.Unauthenticated, err)
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
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
