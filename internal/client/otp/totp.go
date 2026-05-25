// Package otp генерирует одноразовые пароли для клиентских UI
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"
)

const (
	// AlgorithmSHA1 задает HMAC-SHA1 для TOTP
	AlgorithmSHA1 = "SHA1"

	// AlgorithmSHA256 задает HMAC-SHA256 для TOTP
	AlgorithmSHA256 = "SHA256"

	// AlgorithmSHA512 задает HMAC-SHA512 для TOTP
	AlgorithmSHA512 = "SHA512"
)

// GenerateInput содержит параметры расчета TOTP-кода
type GenerateInput struct {
	Secret        string
	Algorithm     string
	Digits        uint32
	PeriodSeconds uint32
	Now           time.Time
}

// Code содержит рассчитанный TOTP-код и данные ротации
type Code struct {
	Value            string
	ExpiresAt        time.Time
	RemainingSeconds uint32
	PeriodSeconds    uint32
}

// GenerateTOTP рассчитывает TOTP-код по RFC 6238
func GenerateTOTP(input GenerateInput) (Code, error) {
	key, err := decodeBase32Secret(input.Secret)
	if err != nil {
		return Code{}, err
	}

	hashFunc, err := hashFuncByAlgorithm(input.Algorithm)
	if err != nil {
		return Code{}, err
	}

	if input.Digits != 6 && input.Digits != 8 {
		return Code{}, fmt.Errorf("otp digits must be 6 or 8")
	}

	if input.PeriodSeconds == 0 {
		return Code{}, fmt.Errorf("otp period seconds must be greater than zero")
	}

	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	counter := uint64(now.Unix()) / uint64(input.PeriodSeconds)
	value := hotp(key, counter, hashFunc, input.Digits)
	remainingSeconds := RemainingSeconds(now, input.PeriodSeconds)

	return Code{
		Value:            value,
		ExpiresAt:        now.Add(time.Duration(remainingSeconds) * time.Second),
		RemainingSeconds: remainingSeconds,
		PeriodSeconds:    input.PeriodSeconds,
	}, nil
}

// RemainingSeconds возвращает число секунд до следующей ротации кода
func RemainingSeconds(now time.Time, periodSeconds uint32) uint32 {
	if periodSeconds == 0 {
		return 0
	}

	remainder := uint32(now.UTC().Unix() % int64(periodSeconds))
	if remainder == 0 {
		return periodSeconds
	}

	return periodSeconds - remainder
}

// MaskSecret возвращает безопасное для отображения представление OTP-секрета
func MaskSecret(secret string) string {
	normalized := normalizeBase32Secret(secret)
	if len(normalized) <= 8 {
		return "********"
	}

	return normalized[:4] + strings.Repeat("*", len(normalized)-8) + normalized[len(normalized)-4:]
}

func hotp(key []byte, counter uint64, hashFunc func() hash.Hash, digits uint32) string {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(hashFunc, key)
	_, _ = mac.Write(counterBytes[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binaryCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	code := binaryCode % pow10(digits)

	return fmt.Sprintf("%0*d", int(digits), code)
}

func decodeBase32Secret(secret string) ([]byte, error) {
	normalized := normalizeBase32Secret(secret)
	if normalized == "" {
		return nil, fmt.Errorf("otp secret is required")
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("decode otp secret: %w", err)
	}

	return key, nil
}

func pow10(digits uint32) uint32 {
	value := uint32(1)
	for i := uint32(0); i < digits; i++ {
		value *= 10
	}
	return value
}

func normalizeBase32Secret(secret string) string {
	normalized := strings.ToUpper(strings.TrimSpace(secret))
	normalized = strings.ReplaceAll(normalized, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.TrimRight(normalized, "=")
	return normalized
}

func hashFuncByAlgorithm(algorithm string) (func() hash.Hash, error) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case AlgorithmSHA1:
		return sha1.New, nil
	case AlgorithmSHA256:
		return sha256.New, nil
	case AlgorithmSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported otp algorithm: %s", algorithm)
	}
}
