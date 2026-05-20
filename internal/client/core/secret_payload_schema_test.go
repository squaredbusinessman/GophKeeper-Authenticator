package core

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSecretPayloadSchemasRoundTrip(t *testing.T) {
	t.Run("login password", func(t *testing.T) {
		payloadBytes, version, err := EncodeLoginPasswordPayload(LoginPasswordPayload{
			Login:    "user@example.com",
			Password: "secret-password",
			URL:      "https://example.com",
			Notes:    "work account",
		})
		if err != nil {
			t.Fatalf("EncodeLoginPasswordPayload() error = %v", err)
		}

		if version != LoginPasswordPayloadSchemaVersion {
			t.Fatalf("schema version = %d, want %d", version, LoginPasswordPayloadSchemaVersion)
		}

		assertJSONPayload(t, payloadBytes)

		decoded, err := DecodeLoginPasswordPayload(payloadBytes, version)
		if err != nil {
			t.Fatalf("DecodeLoginPasswordPayload() error = %v", err)
		}

		if decoded.Login != "user@example.com" {
			t.Fatalf("decoded login = %q, want user@example.com", decoded.Login)
		}

		if decoded.Password != "secret-password" {
			t.Fatalf("decoded password = %q, want secret-password", decoded.Password)
		}
	})

	t.Run("text", func(t *testing.T) {
		payloadBytes, version, err := EncodeTextPayload(TextPayload{
			Text: "plain text secret",
		})
		if err != nil {
			t.Fatalf("EncodeTextPayload() error = %v", err)
		}

		if version != TextPayloadSchemaVersion {
			t.Fatalf("schema version = %d, want %d", version, TextPayloadSchemaVersion)
		}

		assertJSONPayload(t, payloadBytes)

		decoded, err := DecodeTextPayload(payloadBytes, version)
		if err != nil {
			t.Fatalf("DecodeTextPayload() error = %v", err)
		}

		if decoded.Text != "plain text secret" {
			t.Fatalf("decoded text = %q, want plain text secret", decoded.Text)
		}
	})

	t.Run("bank card preserves leading zeroes", func(t *testing.T) {
		payloadBytes, version, err := EncodeBankCardPayload(BankCardPayload{
			Number:          "0000123412341234",
			CardholderName:  "EVGENII ANTROPOV",
			ExpirationMonth: "01",
			ExpirationYear:  "2030",
			CVV:             "007",
			Notes:           "salary card",
		})
		if err != nil {
			t.Fatalf("EncodeBankCardPayload() error = %v", err)
		}

		if version != BankCardPayloadSchemaVersion {
			t.Fatalf("schema version = %d, want %d", version, BankCardPayloadSchemaVersion)
		}

		assertJSONPayload(t, payloadBytes)

		decoded, err := DecodeBankCardPayload(payloadBytes, version)
		if err != nil {
			t.Fatalf("DecodeBankCardPayload() error = %v", err)
		}

		if decoded.Number != "0000123412341234" {
			t.Fatalf("decoded number = %q, want leading zeroes to be preserved", decoded.Number)
		}

		if decoded.CVV != "007" {
			t.Fatalf("decoded cvv = %q, want 007", decoded.CVV)
		}
	})

	t.Run("binary preserves raw bytes", func(t *testing.T) {
		rawData := []byte{0x00, 0x01, 0x02, 0xff}

		payloadBytes, version, err := EncodeBinaryPayload(BinaryPayload{
			FileName:    "token.bin",
			ContentType: "application/octet-stream",
			Data:        rawData,
		})
		if err != nil {
			t.Fatalf("EncodeBinaryPayload() error = %v", err)
		}

		if version != BinaryPayloadSchemaVersion {
			t.Fatalf("schema version = %d, want %d", version, BinaryPayloadSchemaVersion)
		}

		assertJSONPayload(t, payloadBytes)

		decoded, err := DecodeBinaryPayload(payloadBytes, version)
		if err != nil {
			t.Fatalf("DecodeBinaryPayload() error = %v", err)
		}

		if decoded.FileName != "token.bin" {
			t.Fatalf("decoded file name = %q, want token.bin", decoded.FileName)
		}

		if !bytes.Equal(decoded.Data, rawData) {
			t.Fatalf("decoded data = %v, want %v", decoded.Data, rawData)
		}
	})
}

func TestSecretPayloadSchemasValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "login password without login",
			run: func() error {
				_, _, err := EncodeLoginPasswordPayload(LoginPasswordPayload{Password: "secret-password"})
				return err
			},
		},
		{
			name: "login password without password",
			run: func() error {
				_, _, err := EncodeLoginPasswordPayload(LoginPasswordPayload{Login: "user@example.com"})
				return err
			},
		},
		{
			name: "text without text",
			run: func() error {
				_, _, err := EncodeTextPayload(TextPayload{})
				return err
			},
		},
		{
			name: "bank card without number",
			run: func() error {
				_, _, err := EncodeBankCardPayload(BankCardPayload{
					CardholderName:  "EVGENII ANTROPOV",
					ExpirationMonth: "01",
					ExpirationYear:  "2030",
				})
				return err
			},
		},
		{
			name: "binary without data",
			run: func() error {
				_, _, err := EncodeBinaryPayload(BinaryPayload{FileName: "empty.bin"})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err == nil {
				t.Fatalf("error = nil, want validation error")
			}
		})
	}
}

func TestSecretPayloadSchemasRejectUnsupportedVersion(t *testing.T) {
	loginPayload, _, err := EncodeLoginPasswordPayload(LoginPasswordPayload{
		Login:    "user@example.com",
		Password: "secret-password",
	})
	if err != nil {
		t.Fatalf("EncodeLoginPasswordPayload() error = %v", err)
	}

	_, err = DecodeLoginPasswordPayload(loginPayload, LoginPasswordPayloadSchemaVersion+1)
	if err == nil {
		t.Fatalf("DecodeLoginPasswordPayload() error = nil, want unsupported version error")
	}

	textPayload, _, err := EncodeTextPayload(TextPayload{Text: "secret"})
	if err != nil {
		t.Fatalf("EncodeTextPayload() error = %v", err)
	}

	_, err = DecodeTextPayload(textPayload, TextPayloadSchemaVersion+1)
	if err == nil {
		t.Fatalf("DecodeTextPayload() error = nil, want unsupported version error")
	}

	bankCardPayload, _, err := EncodeBankCardPayload(BankCardPayload{
		Number:          "4111111111111111",
		CardholderName:  "EVGENII ANTROPOV",
		ExpirationMonth: "12",
		ExpirationYear:  "2030",
	})
	if err != nil {
		t.Fatalf("EncodeBankCardPayload() error = %v", err)
	}

	_, err = DecodeBankCardPayload(bankCardPayload, BankCardPayloadSchemaVersion+1)
	if err == nil {
		t.Fatalf("DecodeBankCardPayload() error = nil, want unsupported version error")
	}

	binaryPayload, _, err := EncodeBinaryPayload(BinaryPayload{
		FileName:    "token.bin",
		ContentType: "application/octet-stream",
		Data:        []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("EncodeBinaryPayload() error = %v", err)
	}

	_, err = DecodeBinaryPayload(binaryPayload, BinaryPayloadSchemaVersion+1)
	if err == nil {
		t.Fatalf("DecodeBinaryPayload() error = nil, want unsupported version error")
	}
}

func assertJSONPayload(t *testing.T, payload []byte) {
	t.Helper()

	if len(payload) == 0 {
		t.Fatalf("payload is empty")
	}

	if !json.Valid(payload) {
		t.Fatalf("payload = %q, want valid json", payload)
	}
}
