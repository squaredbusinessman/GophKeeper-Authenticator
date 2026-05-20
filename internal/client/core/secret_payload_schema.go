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

// BinaryPayload описывает payload бинарного секрета
type BinaryPayload struct {
	FileName    string `json:"file_name"`
	ContentType string `json:"content_type,omitempty"`
	Data        []byte `json:"data"`
}

func EncodeLoginPasswordPayload(value LoginPasswordPayload) ([]byte, uint32, error) {
	if strings.TrimSpace(value.Login) == "" {
		return nil, 0, fmt.Errorf("login is required")
	}
	if value.Password == "" {
		return nil, 0, fmt.Errorf("password is required")
	}
	return encodePayload(value, LoginPasswordPayloadSchemaVersion)
}

func DecodeLoginPasswordPayload(raw []byte, version uint32) (LoginPasswordPayload, error) {
	return decodePayload[LoginPasswordPayload](raw, version, LoginPasswordPayloadSchemaVersion)
}

func EncodeTextPayload(value TextPayload) ([]byte, uint32, error) {
	if value.Text == "" {
		return nil, 0, fmt.Errorf("text is required")
	}
	return encodePayload(value, TextPayloadSchemaVersion)
}

func DecodeTextPayload(raw []byte, version uint32) (TextPayload, error) {
	return decodePayload[TextPayload](raw, version, TextPayloadSchemaVersion)
}

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

func DecodeBankCardPayload(raw []byte, version uint32) (BankCardPayload, error) {
	return decodePayload[BankCardPayload](raw, version, BankCardPayloadSchemaVersion)
}

func EncodeBinaryPayload(value BinaryPayload) ([]byte, uint32, error) {
	if len(value.Data) == 0 {
		return nil, 0, fmt.Errorf("binary data is required")
	}
	return encodePayload(value, BinaryPayloadSchemaVersion)
}

func DecodeBinaryPayload(raw []byte, version uint32) (BinaryPayload, error) {
	return decodePayload[BinaryPayload](raw, version, BinaryPayloadSchemaVersion)
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
