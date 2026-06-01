package app

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUserFacingErrorMapsCommonClientProblems(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "connection refused",
			err:  fmt.Errorf("login: %w", status.Error(codes.Unavailable, "connection refused")),
			want: "не удалось подключиться к серверу",
		},
		{
			name: "tls config error",
			err:  fmt.Errorf("%w: %w", ErrServerTLSCredentials, errors.New("open missing.crt")),
			want: "не удалось загрузить TLS-сертификат сервера",
		},
		{
			name: "config error",
			err:  fmt.Errorf("%w: %w", ErrClientConfig, config.ErrServerAddressRequired),
			want: "не удалось загрузить конфигурацию клиента",
		},
		{
			name: "version conflict",
			err:  status.Error(codes.FailedPrecondition, "vault item version conflict"),
			want: "актуальной version",
		},
		{
			name: "not found",
			err:  status.Error(codes.NotFound, "item not found"),
			want: "секрет не найден",
		},
		{
			name: "wrong master password",
			err:  fmt.Errorf("open vault: %w", core.ErrInvalidMasterPassword),
			want: "неверный мастер-пароль",
		},
		{
			name: "master passwords mismatch",
			err:  ErrMasterPasswordsMismatch,
			want: "мастер-пароли не совпадают",
		},
		{
			name: "fallback",
			err:  errors.New("third party english error"),
			want: "не удалось выполнить действие",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UserFacingError(tt.err)
			if !strings.Contains(got, tt.want) {
				t.Fatalf("UserFacingError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUserFacingErrorReturnsEmptyForNil(t *testing.T) {
	if got := UserFacingError(nil); got != "" {
		t.Fatalf("UserFacingError(nil) = %q, want empty", got)
	}
}
