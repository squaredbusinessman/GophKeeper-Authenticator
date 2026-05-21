package grpcserver

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// LoggingUnaryInterceptor пишет access-log для unary gRPC-запросов без payload и секретов
func LoggingUnaryInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	if logger == nil {
		logger = zap.NewNop()
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		startedAt := time.Now()

		response, err := handler(ctx, req)

		method := "unknown"
		if info != nil && info.FullMethod != "" {
			method = info.FullMethod
		}

		fields := []zap.Field{
			zap.String("grpc_method", method),
			zap.String("grpc_code", status.Code(err).String()),
			zap.Duration("duration", time.Since(startedAt)),
		}

		if userID, ok := UserIDFromContext(ctx); ok {
			fields = append(fields, zap.String("user_id", userID))
		}

		logger.Info("grpc request completed", fields...)

		return response, err
	}
}
