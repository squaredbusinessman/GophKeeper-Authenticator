package grpcserver

import (
	"context"
	"strings"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/auth/token"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenValidator проверяет access token и возвращает claims пользователя
type TokenValidator interface {
	Validate(rawToken string) (token.Claims, error)
}

type authContextKey struct{}

var userIDContextKey authContextKey

// AuthUnaryInterceptor закрывает приватные unary методы gRPC проверкой access token
func AuthUnaryInterceptor(validator TokenValidator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		fullMethod := ""
		if info != nil {
			fullMethod = info.FullMethod
		}

		if isPublicMethod(fullMethod) {
			return handler(ctx, req)
		}

		if validator == nil {
			return nil, status.Error(codes.Internal, "token validator is not configured")
		}

		rawToken, err := bearerTokenFromContext(ctx)
		if err != nil {
			return nil, err
		}

		claims, err := validator.Validate(rawToken)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid access token")
		}

		userID := strings.TrimSpace(claims.UserID)
		if userID == "" {
			return nil, status.Error(codes.Unauthenticated, "invalid access token")
		}

		return handler(contextWithUserID(ctx, userID), req)
	}
}

// UserIDFromContext достает user id, который middleware положил в context
func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDContextKey).(string)
	if !ok || strings.TrimSpace(userID) == "" {
		return "", false
	}

	return userID, true
}

func contextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDContextKey, userID)
}

func isPublicMethod(method string) bool {
	switch method {
	case gophkeeperv1.AuthService_Register_FullMethodName,
		gophkeeperv1.AuthService_Login_FullMethodName:
		return true
	default:
		return false
	}
}

func bearerTokenFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "authorization metadata is required")
	}

	values := md.Get("authorization")
	for _, value := range values {
		rawToken, ok := parseBearerToken(value)
		if ok {
			return rawToken, nil
		}
	}

	return "", status.Error(codes.Unauthenticated, "bearer token is required")
}

func parseBearerToken(value string) (string, bool) {
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return "", false
	}

	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}

	return parts[1], true
}
