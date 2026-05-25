package app

import (
	"errors"
	"strings"
	"testing"

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
			err:  errors.New(`login: rpc error: code = Unavailable desc = connection error: dial tcp 127.0.0.1:9090: connect: connection refused`),
			want: "не удалось подключиться к серверу",
		},
		{
			name: "tls config error",
			err:  errors.New("load server TLS credentials: open missing.crt: no such file or directory"),
			want: "не удалось загрузить TLS-сертификат сервера",
		},
		{
			name: "config error",
			err:  errors.New("error loading config: validate client config: server address is required"),
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
			err:  errors.New("open vault: login: could not decrypt vault key: cipher: message authentication failed"),
			want: "неверный мастер-пароль",
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
