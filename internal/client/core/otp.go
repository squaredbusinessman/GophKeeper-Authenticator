package core

import (
	"fmt"
	"time"

	clientotp "github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/otp"
)

// OTPCode содержит текущий OTP-код и данные ротации для UI
type OTPCode struct {
	Value            string
	ExpiresAt        time.Time
	RemainingSeconds uint32
	PeriodSeconds    uint32
}

// CurrentOTPCode рассчитывает текущий OTP-код из client core payload
func CurrentOTPCode(payload OTPPayload, now time.Time) (OTPCode, error) {
	normalized, err := normalizeOTPPayload(payload)
	if err != nil {
		return OTPCode{}, err
	}

	code, err := clientotp.GenerateTOTP(clientotp.GenerateInput{
		Secret:        normalized.Secret,
		Algorithm:     normalized.Algorithm,
		Digits:        normalized.Digits,
		PeriodSeconds: normalized.PeriodSeconds,
		Now:           now,
	})
	if err != nil {
		return OTPCode{}, fmt.Errorf("generate otp code: %w", err)
	}

	return OTPCode{
		Value:            code.Value,
		ExpiresAt:        code.ExpiresAt,
		RemainingSeconds: code.RemainingSeconds,
		PeriodSeconds:    code.PeriodSeconds,
	}, nil
}

// MaskOTPSecret возвращает безопасное для отображения представление OTP-секрета
func MaskOTPSecret(secret string) string {
	return clientotp.MaskSecret(secret)
}
