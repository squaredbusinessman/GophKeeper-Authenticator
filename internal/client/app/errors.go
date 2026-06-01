package app

import (
	"errors"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrClientConfig означает ошибку загрузки или проверки клиентской конфигурации
	ErrClientConfig = errors.New("client config error")
	// ErrServerTLSCredentials означает ошибку загрузки TLS-настроек клиента
	ErrServerTLSCredentials = errors.New("server TLS credentials error")
	// ErrMasterPasswordsMismatch означает несовпадение мастер-пароля и его повтора
	ErrMasterPasswordsMismatch = errors.New("master passwords do not match")
	// ErrVaultSessionClosed означает отсутствие открытой vault-сессии
	ErrVaultSessionClosed = errors.New("vault session is not open")
	// ErrBlobServiceRequired означает отсутствие сервиса для binary-секретов
	ErrBlobServiceRequired = errors.New("blob service is required")
	// ErrOutputDirectoryRequired означает пустой путь к папке сохранения
	ErrOutputDirectoryRequired = errors.New("output directory is required")
	// ErrOutputDirectoryNotDirectory означает, что путь сохранения не является папкой
	ErrOutputDirectoryNotDirectory = errors.New("output directory is not a directory")
	// ErrOutputFileExists означает, что файл сохранения уже существует
	ErrOutputFileExists = errors.New("output file already exists")
)

// UserFacingError возвращает безопасный текст ошибки для клиентских UI
func UserFacingError(err error) string {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, ErrClientConfig):
		return "не удалось загрузить конфигурацию клиента. Проверьте переменные окружения GOPHKEEPER_SERVER_ADDRESS, GOPHKEEPER_SERVER_TLS_CERT_FILE и GOPHKEEPER_TOKEN_FILE"
	case errors.Is(err, config.ErrServerAddressRequired):
		return "не указан адрес сервера. Проверьте переменную окружения GOPHKEEPER_SERVER_ADDRESS"
	case errors.Is(err, config.ErrTokenFileRequired):
		return "не указан файл токена. Проверьте переменную окружения GOPHKEEPER_TOKEN_FILE"
	case errors.Is(err, config.ErrServerTLSCertFileRequired):
		return "не указан TLS-сертификат сервера. Проверьте переменную окружения GOPHKEEPER_SERVER_TLS_CERT_FILE"
	case errors.Is(err, ErrServerTLSCredentials):
		return "не удалось загрузить TLS-сертификат сервера. Проверьте путь GOPHKEEPER_SERVER_TLS_CERT_FILE"
	case errors.Is(err, ErrMasterPasswordsMismatch):
		return "мастер-пароли не совпадают"
	case errors.Is(err, core.ErrInvalidMasterPassword):
		return "неверный мастер-пароль: vault key не удалось расшифровать"
	case errors.Is(err, ErrVaultSessionClosed):
		return "vault-сессия не открыта. Выполните вход и повторите действие"
	case errors.Is(err, ErrBlobServiceRequired):
		return "сервис binary-секретов недоступен"
	case errors.Is(err, ErrOutputDirectoryRequired):
		return "укажите папку для сохранения binary-секрета"
	case errors.Is(err, ErrOutputDirectoryNotDirectory):
		return "путь для сохранения binary-секрета должен быть папкой"
	case errors.Is(err, ErrOutputFileExists):
		return "файл для сохранения binary-секрета уже существует. Укажите другую папку для сохранения, чтобы не перезаписать существующий файл"
	}

	switch status.Code(err) {
	case codes.AlreadyExists:
		return "пользователь с таким login уже существует. Выполните login или выберите другой login для регистрации"
	case codes.Unauthenticated:
		return "неверный login или пароль входа"
	case codes.Unavailable:
		return "не удалось подключиться к серверу. Проверьте, что gophkeeper-server запущен и адрес GOPHKEEPER_SERVER_ADDRESS указан верно"
	case codes.FailedPrecondition:
		return "version conflict: версия секрета устарела. Выполните gophkeeper list или gophkeeper sync и повторите команду с актуальной version"
	case codes.Aborted:
		return "version conflict: версия секрета устарела. Выполните gophkeeper list или gophkeeper sync и повторите команду с актуальной version"
	case codes.NotFound:
		return "секрет не найден. Проверьте Secret ID через gophkeeper list или gophkeeper sync"
	case codes.PermissionDenied:
		return "нет доступа к этому секрету"
	case codes.InvalidArgument:
		return "некорректные данные команды. Проверьте обязательные поля и повторите ввод"
	case codes.Internal:
		return "внутренняя ошибка сервера. Проверьте логи gophkeeper-server"
	default:
		return "не удалось выполнить действие. Проверьте ввод, состояние сервера и повторите команду"
	}
}
