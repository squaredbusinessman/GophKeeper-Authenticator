package app

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UserFacingError возвращает безопасный текст ошибки для клиентских UI
func UserFacingError(err error) string {
	if err == nil {
		return ""
	}

	message := err.Error()
	lowerMessage := strings.ToLower(message)

	switch {
	case strings.Contains(lowerMessage, "error loading config"):
		return "не удалось загрузить конфигурацию клиента. Проверьте переменные окружения GOPHKEEPER_SERVER_ADDRESS, GOPHKEEPER_SERVER_TLS_ENABLED, GOPHKEEPER_SERVER_TLS_CERT_FILE и GOPHKEEPER_TOKEN_FILE"
	case strings.Contains(lowerMessage, "load server tls credentials"):
		return "не удалось загрузить TLS-сертификат сервера. Проверьте путь GOPHKEEPER_SERVER_TLS_CERT_FILE"
	case strings.Contains(lowerMessage, "string field contains invalid utf-8"):
		return "введенные данные содержат недопустимые символы. Используйте UTF-8 символы для login и пароля входа"
	case strings.Contains(lowerMessage, "output file already exists"):
		return "файл для сохранения binary-секрета уже существует. Укажите другой Output path, чтобы не перезаписать существующий файл"
	case strings.Contains(lowerMessage, "invalid credentials"):
		return "неверный login или пароль входа"
	case strings.Contains(lowerMessage, "login already exists"):
		return "пользователь с таким login уже существует. Выполните login или выберите другой login для регистрации"
	case strings.Contains(lowerMessage, "connection refused") ||
		strings.Contains(lowerMessage, "error while dialing") ||
		strings.Contains(lowerMessage, "code = unavailable"):
		return "не удалось подключиться к серверу. Проверьте, что gophkeeper-server запущен и адрес GOPHKEEPER_SERVER_ADDRESS указан верно"
	case strings.Contains(lowerMessage, "version conflict") ||
		strings.Contains(lowerMessage, "code = failedprecondition"):
		return "version conflict: версия секрета устарела. Выполните gophkeeper list или gophkeeper sync и повторите команду с актуальной version"
	case strings.Contains(lowerMessage, "could not decrypt vault key") ||
		strings.Contains(lowerMessage, "message authentication failed"):
		return "неверный мастер-пароль: vault key не удалось расшифровать"
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
		return message
	}
}
