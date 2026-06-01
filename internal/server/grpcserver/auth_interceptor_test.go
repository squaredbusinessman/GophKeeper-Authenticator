package grpcserver

import (
	"context"
	"errors"
	"testing"
	"time"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/token"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/config"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeTokenValidator struct {
	claims token.Claims
	err    error
	calls  []string
}

func (v *fakeTokenValidator) Validate(rawToken string) (token.Claims, error) {
	v.calls = append(v.calls, rawToken)
	if v.err != nil {
		return token.Claims{}, v.err
	}

	return v.claims, nil
}

func testUnaryHandler(t *testing.T, called *bool) grpc.UnaryHandler {
	t.Helper()

	return func(ctx context.Context, req any) (any, error) {
		*called = true
		return "ok", nil
	}
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s fakeServerStream) Context() context.Context {
	return s.ctx
}

func TestAuthUnaryInterceptorAllowsPublicMethodsWithoutToken(t *testing.T) {
	publicMethods := []string{
		gophkeeperv1.AuthService_Register_FullMethodName,
		gophkeeperv1.AuthService_Login_FullMethodName,
	}

	for _, method := range publicMethods {
		t.Run(method, func(t *testing.T) {
			validator := &fakeTokenValidator{}
			interceptor := AuthUnaryInterceptor(validator)
			called := false

			response, err := interceptor(
				context.Background(),
				nil,
				&grpc.UnaryServerInfo{FullMethod: method},
				testUnaryHandler(t, &called),
			)
			if err != nil {
				t.Fatalf("interceptor() error = %v", err)
			}

			if response != "ok" {
				t.Fatalf("response = %v, want ok", response)
			}

			if !called {
				t.Fatalf("handler was not called")
			}

			if len(validator.calls) != 0 {
				t.Fatalf("validator calls = %d, want 0", len(validator.calls))
			}
		})
	}
}

func TestAuthStreamInterceptorAddsUserIDToContext(t *testing.T) {
	validator := &fakeTokenValidator{
		claims: token.Claims{UserID: "user-id"},
	}
	interceptor := AuthStreamInterceptor(validator)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer access-token"))
	called := false

	err := interceptor(
		nil,
		fakeServerStream{ctx: ctx},
		&grpc.StreamServerInfo{FullMethod: gophkeeperv1.BlobService_UploadBlob_FullMethodName},
		func(_ any, stream grpc.ServerStream) error {
			called = true
			userID, ok := UserIDFromContext(stream.Context())
			if !ok {
				t.Fatalf("user id missing from stream context")
			}
			if userID != "user-id" {
				t.Fatalf("user id = %q, want user-id", userID)
			}

			return nil
		},
	)
	if err != nil {
		t.Fatalf("interceptor() error = %v", err)
	}
	if !called {
		t.Fatalf("handler was not called")
	}
	if len(validator.calls) != 1 || validator.calls[0] != "access-token" {
		t.Fatalf("validator calls = %v, want access-token", validator.calls)
	}
}

func TestAuthStreamInterceptorRejectsProtectedMethodWithoutMetadata(t *testing.T) {
	interceptor := AuthStreamInterceptor(&fakeTokenValidator{})

	err := interceptor(
		nil,
		fakeServerStream{ctx: context.Background()},
		&grpc.StreamServerInfo{FullMethod: gophkeeperv1.BlobService_DownloadBlob_FullMethodName},
		func(any, grpc.ServerStream) error {
			t.Fatalf("handler was called")
			return nil
		},
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want Unauthenticated", status.Code(err))
	}
}

func TestAuthUnaryInterceptorRejectsProtectedMethodWithoutMetadata(t *testing.T) {
	protectedMethods := []string{
		gophkeeperv1.VaultService_CreateItem_FullMethodName,
		gophkeeperv1.VaultService_GetItem_FullMethodName,
		gophkeeperv1.VaultService_ListItems_FullMethodName,
		gophkeeperv1.VaultService_UpdateItem_FullMethodName,
		gophkeeperv1.VaultService_DeleteItem_FullMethodName,
		gophkeeperv1.VaultService_Sync_FullMethodName,
	}

	for _, method := range protectedMethods {
		t.Run(method, func(t *testing.T) {
			validator := &fakeTokenValidator{}
			interceptor := AuthUnaryInterceptor(validator)
			called := false

			_, err := interceptor(
				context.Background(),
				nil,
				&grpc.UnaryServerInfo{FullMethod: method},
				testUnaryHandler(t, &called),
			)
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("code = %s, want %s, err = %v", status.Code(err), codes.Unauthenticated, err)
			}

			if called {
				t.Fatalf("handler was called")
			}
		})
	}
}

func TestAuthUnaryInterceptorRejectsProtectedMethodWithoutBearerToken(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{
			name:  "empty authorization",
			value: "",
		},
		{
			name:  "basic authorization",
			value: "Basic token",
		},
		{
			name:  "bearer without token",
			value: "Bearer ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &fakeTokenValidator{}
			interceptor := AuthUnaryInterceptor(validator)
			called := false
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", tt.value))

			_, err := interceptor(
				ctx,
				nil,
				&grpc.UnaryServerInfo{FullMethod: gophkeeperv1.VaultService_ListItems_FullMethodName},
				testUnaryHandler(t, &called),
			)
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("code = %s, want %s, err = %v", status.Code(err), codes.Unauthenticated, err)
			}

			if called {
				t.Fatalf("handler was called")
			}

			if len(validator.calls) != 0 {
				t.Fatalf("validator calls = %d, want 0", len(validator.calls))
			}
		})
	}
}

func TestAuthUnaryInterceptorRejectsInvalidToken(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "invalid token",
			err:  token.ErrInvalidToken,
		},
		{
			name: "expired token",
			err:  token.ErrExpiredToken,
		},
		{
			name: "unexpected validator error",
			err:  errors.New("validator failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &fakeTokenValidator{err: tt.err}
			interceptor := AuthUnaryInterceptor(validator)
			called := false
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer access-token"))

			_, err := interceptor(
				ctx,
				nil,
				&grpc.UnaryServerInfo{FullMethod: gophkeeperv1.VaultService_ListItems_FullMethodName},
				testUnaryHandler(t, &called),
			)
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("code = %s, want %s, err = %v", status.Code(err), codes.Unauthenticated, err)
			}

			if called {
				t.Fatalf("handler was called")
			}

			if len(validator.calls) != 1 || validator.calls[0] != "access-token" {
				t.Fatalf("validator calls = %v, want access-token", validator.calls)
			}
		})
	}
}

func TestAuthUnaryInterceptorAddsUserIDToContextForProtectedMethod(t *testing.T) {
	validator := &fakeTokenValidator{
		claims: token.Claims{
			UserID:    "user-id-1",
			ExpiresAt: time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		},
	}
	interceptor := AuthUnaryInterceptor(validator)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer access-token"))

	response, err := interceptor(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: gophkeeperv1.VaultService_ListItems_FullMethodName},
		func(ctx context.Context, req any) (any, error) {
			userID, ok := UserIDFromContext(ctx)
			if !ok {
				t.Fatalf("user id is missing in context")
			}

			if userID != "user-id-1" {
				t.Fatalf("user id = %q, want %q", userID, "user-id-1")
			}

			return "ok", nil
		},
	)
	if err != nil {
		t.Fatalf("interceptor() error = %v", err)
	}

	if response != "ok" {
		t.Fatalf("response = %v, want ok", response)
	}
}

func TestNewProtectsVaultServiceWithAuthInterceptor(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	cfg := &config.Config{
		GRPCAddress:       "127.0.0.1:0",
		GRPCTLSCertFile:   certFile,
		GRPCTLSKeyFile:    keyFile,
		AccessTokenSecret: "test-access-token-secret-32-bytes",
		AccessTokenTTL:    time.Minute,
	}

	server, err := New(cfg, zap.NewNop(), nil, nil)
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

	_, err = client.ListItems(ctx, gophkeeperv1.ListItemsRequest_builder{}.Build())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want %s, err = %v", status.Code(err), codes.Unauthenticated, err)
	}
}
