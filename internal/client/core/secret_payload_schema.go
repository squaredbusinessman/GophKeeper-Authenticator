package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// LoginPasswordPayloadSchemaVersion версия схемы payload для login/password секрета
	LoginPasswordPayloadSchemaVersion uint32 = 1

	// TextPayloadSchemaVersion версия схемы payload для текстового секрета
	TextPayloadSchemaVersion uint32 = 1

	// BankCardPayloadSchemaVersion версия схемы payload для банковской карты
	BankCardPayloadSchemaVersion uint32 = 1

	// BinaryPayloadSchemaVersion версия схемы payload для бинарного секрета
	BinaryPayloadSchemaVersion uint32 = 1

	// OTPPayloadSchemaVersion версия схемы payload для OTP секрета
	OTPPayloadSchemaVersion uint32 = 1

	// DefaultOTPPeriodSeconds задает период ротации OTP-кода по умолчанию
	DefaultOTPPeriodSeconds = 30
)

// LoginPasswordPayload описывает payload секрета с логином и паролем
type LoginPasswordPayload struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// TextPayload описывает payload текстового секрета
type TextPayload struct {
	Text string `json:"text"`
}

// BankCardPayload описывает payload банковской карты
type BankCardPayload struct {
	Number          string `json:"number"`
	CardholderName  string `json:"cardholder_name"`
	ExpirationMonth string `json:"expiration_month"`
	ExpirationYear  string `json:"expiration_year"`
	CVV             string `json:"cvv,omitempty"`
	Notes           string `json:"notes,omitempty"`
}

// BinaryPayload описывает metadata payload бинарного секрета
type BinaryPayload struct {
	FileName       string `json:"file_name"`
	ContentType    string `json:"content_type,omitempty"`
	SizeBytes      int64  `json:"size_bytes"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	BlobID         string `json:"blob_id"`
}

// OTPPayload описывает payload секрета с одноразовым паролем
type OTPPayload struct {
	Issuer        string `json:"issuer,omitempty"`
	AccountName   string `json:"account_name"`
	Secret        string `json:"secret"`
	Algorithm     string `json:"algorithm"`
	Digits        uint32 `json:"digits"`
	PeriodSeconds uint32 `json:"period_seconds"`
	Notes         string `json:"notes,omitempty"`
}

// EncodeLoginPasswordPayload валидирует и кодирует login/password payload в JSON-схему
func EncodeLoginPasswordPayload(value LoginPasswordPayload) ([]byte, uint32, error) {
	if strings.TrimSpace(value.Login) == "" {
		return nil, 0, fmt.Errorf("login is required")
	}
	if value.Password == "" {
		return nil, 0, fmt.Errorf("password is required")
	}
	return encodePayload(value, LoginPasswordPayloadSchemaVersion)
}

// DecodeLoginPasswordPayload декодирует login/password payload с проверкой версии схемы
func DecodeLoginPasswordPayload(raw []byte, version uint32) (LoginPasswordPayload, error) {
	return decodePayload[LoginPasswordPayload](raw, version, LoginPasswordPayloadSchemaVersion)
}

// EncodeTextPayload валидирует и кодирует text payload в JSON-схему
func EncodeTextPayload(value TextPayload) ([]byte, uint32, error) {
	if value.Text == "" {
		return nil, 0, fmt.Errorf("text is required")
	}
	return encodePayload(value, TextPayloadSchemaVersion)
}

// DecodeTextPayload декодирует text payload с проверкой версии схемы
func DecodeTextPayload(raw []byte, version uint32) (TextPayload, error) {
	return decodePayload[TextPayload](raw, version, TextPayloadSchemaVersion)
}

// EncodeBankCardPayload валидирует и кодирует bank card payload в JSON-схему
func EncodeBankCardPayload(value BankCardPayload) ([]byte, uint32, error) {
	if strings.TrimSpace(value.Number) == "" {
		return nil, 0, fmt.Errorf("card number is required")
	}
	if strings.TrimSpace(value.CardholderName) == "" {
		return nil, 0, fmt.Errorf("cardholder name is required")
	}
	if strings.TrimSpace(value.ExpirationMonth) == "" {
		return nil, 0, fmt.Errorf("expiration month is required")
	}
	if strings.TrimSpace(value.ExpirationYear) == "" {
		return nil, 0, fmt.Errorf("expiration year is required")
	}
	return encodePayload(value, BankCardPayloadSchemaVersion)
}

// DecodeBankCardPayload декодирует bank card payload с проверкой версии схемы
func DecodeBankCardPayload(raw []byte, version uint32) (BankCardPayload, error) {
	return decodePayload[BankCardPayload](raw, version, BankCardPayloadSchemaVersion)
}

// EncodeBinaryPayload валидирует binary payload metadata и кодирует JSON-схему
func EncodeBinaryPayload(value BinaryPayload) ([]byte, uint32, error) {
	if strings.TrimSpace(value.FileName) == "" {
		return nil, 0, fmt.Errorf("file name is required")
	}

	if value.SizeBytes <= 0 {
		return nil, 0, fmt.Errorf("binary size is required")
	}

	if strings.TrimSpace(value.ChecksumSHA256) == "" {
		return nil, 0, fmt.Errorf("binary checksum is required")
	}

	if strings.TrimSpace(value.BlobID) == "" {
		return nil, 0, fmt.Errorf("binary blob id is required")
	}

	value.FileName = strings.TrimSpace(value.FileName)
	value.ContentType = strings.TrimSpace(value.ContentType)
	value.ChecksumSHA256 = strings.TrimSpace(value.ChecksumSHA256)
	value.BlobID = strings.TrimSpace(value.BlobID)

	return encodePayload(value, BinaryPayloadSchemaVersion)
}

// DecodeBinaryPayload декодирует binary payload metadata
func DecodeBinaryPayload(raw []byte, version uint32) (BinaryPayload, error) {
	value, err := decodePayload[BinaryPayload](raw, version, BinaryPayloadSchemaVersion)
	if err != nil {
		return BinaryPayload{}, err
	}

	if strings.TrimSpace(value.FileName) == "" {
		return BinaryPayload{}, fmt.Errorf("file name is required")
	}

	if value.SizeBytes <= 0 {
		return BinaryPayload{}, fmt.Errorf("binary size is required")
	}

	if strings.TrimSpace(value.ChecksumSHA256) == "" {
		return BinaryPayload{}, fmt.Errorf("binary checksum is required")
	}

	if strings.TrimSpace(value.BlobID) == "" {
		return BinaryPayload{}, fmt.Errorf("binary blob id is required")
	}

	value.FileName = strings.TrimSpace(value.FileName)
	value.ContentType = strings.TrimSpace(value.ContentType)
	value.ChecksumSHA256 = strings.TrimSpace(value.ChecksumSHA256)
	value.BlobID = strings.TrimSpace(value.BlobID)

	return value, nil
}

// EncodeOTPPayload валидирует и кодирует OTP payload в JSON-схему
func EncodeOTPPayload(value OTPPayload) ([]byte, uint32, error) {
	normalized, err := normalizeOTPPayload(value)
	if err != nil {
		return nil, 0, err
	}

	return encodePayload(normalized, OTPPayloadSchemaVersion)
}

// DecodeOTPPayload декодирует OTP payload с проверкой версии схемы
func DecodeOTPPayload(raw []byte, version uint32) (OTPPayload, error) {
	value, err := decodePayload[OTPPayload](raw, version, OTPPayloadSchemaVersion)
	if err != nil {
		return OTPPayload{}, err
	}

	return normalizeOTPPayload(value)
}

func normalizeOTPPayload(value OTPPayload) (OTPPayload, error) {
	value.Issuer = strings.TrimSpace(value.Issuer)
	value.AccountName = strings.TrimSpace(value.AccountName)
	value.Secret = strings.TrimSpace(value.Secret)
	value.Algorithm = strings.ToUpper(strings.TrimSpace(value.Algorithm))
	value.Notes = strings.TrimSpace(value.Notes)

	if value.Secret == "" {
		return OTPPayload{}, fmt.Errorf("otp secret is required")
	}

	switch value.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return OTPPayload{}, fmt.Errorf("unsupported otp algorithm: %s", value.Algorithm)
	}

	switch value.Digits {
	case 6, 8:
	default:
		return OTPPayload{}, fmt.Errorf("otp digits must be 6 or 8")
	}

	if value.PeriodSeconds == 0 {
		value.PeriodSeconds = DefaultOTPPeriodSeconds
	}

	return value, nil
}

func encodePayload[T any](value T, version uint32) ([]byte, uint32, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, 0, fmt.Errorf("encode payload schema: %w", err)
	}
	return raw, version, nil
}

func decodePayload[T any](raw []byte, version uint32, supportedVersion uint32) (T, error) {
	var value T

	if version != supportedVersion {
		return value, fmt.Errorf("unsupported payload schema version: %d", version)
	}

	if err := json.Unmarshal(raw, &value); err != nil {
		return value, fmt.Errorf("decode payload schema: %w", err)
	}

	return value, nil
}
