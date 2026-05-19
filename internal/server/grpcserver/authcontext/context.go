// Package authcontext хранит данные аутентифицированного пользователя в context
package authcontext

import (
	"context"
	"strings"
)

type userIDContextKey struct{}

// ContextWithUserID добавляет user id в context
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDContextKey{}, userID)
}

// UserIDFromContext достает user id из context
func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDContextKey{}).(string)
	if !ok || strings.TrimSpace(userID) == "" {
		return "", false
	}

	return userID, true
}
