package grpcserver

import (
	"context"
	"testing"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver/authcontext"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLoggingUnaryInterceptorWritesAccessLogWithoutRequestPayload(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	interceptor := LoggingUnaryInterceptor(logger)
	ctx := authcontext.ContextWithUserID(context.Background(), "user-1")

	_, err := interceptor(
		ctx,
		"secret request payload",
		&grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.VaultService/ListItems"},
		func(context.Context, any) (any, error) {
			return nil, status.Error(codes.NotFound, "item not found")
		},
	)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %s, want %s", status.Code(err), codes.NotFound)
	}

	if logs.Len() != 1 {
		t.Fatalf("logs count = %d, want 1", logs.Len())
	}

	entry := logs.All()[0]
	if entry.Message != "grpc request completed" {
		t.Fatalf("message = %q, want grpc request completed", entry.Message)
	}

	if entry.Level != zap.WarnLevel {
		t.Fatalf("level = %s, want warn", entry.Level)
	}

	fields := entry.ContextMap()
	if fields["grpc_method"] != "/gophkeeper.v1.VaultService/ListItems" {
		t.Fatalf("grpc_method = %v, want full method", fields["grpc_method"])
	}

	if fields["grpc_code"] != codes.NotFound.String() {
		t.Fatalf("grpc_code = %v, want %s", fields["grpc_code"], codes.NotFound)
	}

	if fields["user_id"] != "user-1" {
		t.Fatalf("user_id = %v, want user-1", fields["user_id"])
	}

	if _, ok := fields["duration"]; !ok {
		t.Fatalf("duration field is missing")
	}

	for key, value := range fields {
		if value == "secret request payload" {
			t.Fatalf("log field %q leaked request payload", key)
		}
	}
}

func TestLoggingUnaryInterceptorHandlesNilLoggerAndNilInfo(t *testing.T) {
	interceptor := LoggingUnaryInterceptor(nil)

	response, err := interceptor(
		context.Background(),
		nil,
		nil,
		func(context.Context, any) (any, error) {
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

func TestLoggingUnaryInterceptorLogsInternalErrorsAtErrorLevel(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	interceptor := LoggingUnaryInterceptor(logger)

	_, err := interceptor(
		context.Background(),
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.AuthService/Login"},
		func(context.Context, any) (any, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	)
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %s, want %s", status.Code(err), codes.Internal)
	}

	if logs.Len() != 1 {
		t.Fatalf("logs count = %d, want 1", logs.Len())
	}

	entry := logs.All()[0]
	if entry.Level != zap.ErrorLevel {
		t.Fatalf("level = %s, want error", entry.Level)
	}
}
