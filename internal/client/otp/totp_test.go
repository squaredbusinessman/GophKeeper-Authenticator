package otp

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerateTOTPMatchesRFC6238Vectors(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		algorithm string
		unixTime  int64
		want      string
	}{
		{
			name:      "sha1 59",
			secret:    base32Secret("12345678901234567890"),
			algorithm: AlgorithmSHA1,
			unixTime:  59,
			want:      "94287082",
		},
		{
			name:      "sha256 59",
			secret:    base32Secret("12345678901234567890123456789012"),
			algorithm: AlgorithmSHA256,
			unixTime:  59,
			want:      "46119246",
		},
		{
			name:      "sha512 59",
			secret:    base32Secret("1234567890123456789012345678901234567890123456789012345678901234"),
			algorithm: AlgorithmSHA512,
			unixTime:  59,
			want:      "90693936",
		},
		{
			name:      "sha1 1111111109",
			secret:    base32Secret("12345678901234567890"),
			algorithm: AlgorithmSHA1,
			unixTime:  1111111109,
			want:      "07081804",
		},
		{
			name:      "sha256 1111111109",
			secret:    base32Secret("12345678901234567890123456789012"),
			algorithm: AlgorithmSHA256,
			unixTime:  1111111109,
			want:      "68084774",
		},
		{
			name:      "sha512 1111111109",
			secret:    base32Secret("1234567890123456789012345678901234567890123456789012345678901234"),
			algorithm: AlgorithmSHA512,
			unixTime:  1111111109,
			want:      "25091201",
		},
		{
			name:      "sha1 1111111111",
			secret:    base32Secret("12345678901234567890"),
			algorithm: AlgorithmSHA1,
			unixTime:  1111111111,
			want:      "14050471",
		},
		{
			name:      "sha256 1111111111",
			secret:    base32Secret("12345678901234567890123456789012"),
			algorithm: AlgorithmSHA256,
			unixTime:  1111111111,
			want:      "67062674",
		},
		{
			name:      "sha512 1111111111",
			secret:    base32Secret("1234567890123456789012345678901234567890123456789012345678901234"),
			algorithm: AlgorithmSHA512,
			unixTime:  1111111111,
			want:      "99943326",
		},
		{
			name:      "sha1 1234567890",
			secret:    base32Secret("12345678901234567890"),
			algorithm: AlgorithmSHA1,
			unixTime:  1234567890,
			want:      "89005924",
		},
		{
			name:      "sha256 1234567890",
			secret:    base32Secret("12345678901234567890123456789012"),
			algorithm: AlgorithmSHA256,
			unixTime:  1234567890,
			want:      "91819424",
		},
		{
			name:      "sha512 1234567890",
			secret:    base32Secret("1234567890123456789012345678901234567890123456789012345678901234"),
			algorithm: AlgorithmSHA512,
			unixTime:  1234567890,
			want:      "93441116",
		},
		{
			name:      "sha1 2000000000",
			secret:    base32Secret("12345678901234567890"),
			algorithm: AlgorithmSHA1,
			unixTime:  2000000000,
			want:      "69279037",
		},
		{
			name:      "sha256 2000000000",
			secret:    base32Secret("12345678901234567890123456789012"),
			algorithm: AlgorithmSHA256,
			unixTime:  2000000000,
			want:      "90698825",
		},
		{
			name:      "sha512 2000000000",
			secret:    base32Secret("1234567890123456789012345678901234567890123456789012345678901234"),
			algorithm: AlgorithmSHA512,
			unixTime:  2000000000,
			want:      "38618901",
		},
		{
			name:      "sha1 20000000000",
			secret:    base32Secret("12345678901234567890"),
			algorithm: AlgorithmSHA1,
			unixTime:  20000000000,
			want:      "65353130",
		},
		{
			name:      "sha256 20000000000",
			secret:    base32Secret("12345678901234567890123456789012"),
			algorithm: AlgorithmSHA256,
			unixTime:  20000000000,
			want:      "77737706",
		},
		{
			name:      "sha512 20000000000",
			secret:    base32Secret("1234567890123456789012345678901234567890123456789012345678901234"),
			algorithm: AlgorithmSHA512,
			unixTime:  20000000000,
			want:      "47863826",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := GenerateTOTP(GenerateInput{
				Secret:        tt.secret,
				Algorithm:     tt.algorithm,
				Digits:        8,
				PeriodSeconds: 30,
				Now:           time.Unix(tt.unixTime, 0),
			})
			if err != nil {
				t.Fatalf("GenerateTOTP() error = %v", err)
			}

			if code.Value != tt.want {
				t.Fatalf("code = %q, want %q", code.Value, tt.want)
			}
		})
	}
}

func TestGenerateTOTPReturnsSixDigitCode(t *testing.T) {
	code, err := GenerateTOTP(GenerateInput{
		Secret:        base32Secret("12345678901234567890"),
		Algorithm:     AlgorithmSHA1,
		Digits:        6,
		PeriodSeconds: 30,
		Now:           time.Unix(59, 0),
	})
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}

	if code.Value != "287082" {
		t.Fatalf("code = %q, want 287082", code.Value)
	}
}

func TestGenerateTOTPRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input GenerateInput
	}{
		{
			name: "invalid base32 secret",
			input: GenerateInput{
				Secret:        "NOT@BASE32",
				Algorithm:     AlgorithmSHA1,
				Digits:        6,
				PeriodSeconds: 30,
				Now:           time.Unix(59, 0),
			},
		},
		{
			name: "unsupported algorithm",
			input: GenerateInput{
				Secret:        base32Secret("12345678901234567890"),
				Algorithm:     "MD5",
				Digits:        6,
				PeriodSeconds: 30,
				Now:           time.Unix(59, 0),
			},
		},
		{
			name: "unsupported digits",
			input: GenerateInput{
				Secret:        base32Secret("12345678901234567890"),
				Algorithm:     AlgorithmSHA1,
				Digits:        7,
				PeriodSeconds: 30,
				Now:           time.Unix(59, 0),
			},
		},
		{
			name: "zero period",
			input: GenerateInput{
				Secret:    base32Secret("12345678901234567890"),
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Now:       time.Unix(59, 0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateTOTP(tt.input)
			if err == nil {
				t.Fatalf("GenerateTOTP() error = nil, want error")
			}
		})
	}
}

func TestRemainingSeconds(t *testing.T) {
	tests := []struct {
		unixTime int64
		period   uint32
		want     uint32
	}{
		{unixTime: 59, period: 30, want: 1},
		{unixTime: 60, period: 30, want: 30},
		{unixTime: 61, period: 30, want: 29},
		{unixTime: 61, period: 0, want: 0},
	}

	for _, tt := range tests {
		got := RemainingSeconds(time.Unix(tt.unixTime, 0), tt.period)
		if got != tt.want {
			t.Fatalf("RemainingSeconds(%d, %d) = %d, want %d", tt.unixTime, tt.period, got, tt.want)
		}
	}
}

func TestGenerateTOTPReturnsExpiration(t *testing.T) {
	now := time.Unix(59, 0)
	code, err := GenerateTOTP(GenerateInput{
		Secret:        base32Secret("12345678901234567890"),
		Algorithm:     AlgorithmSHA1,
		Digits:        6,
		PeriodSeconds: 30,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}

	if code.RemainingSeconds != 1 {
		t.Fatalf("remaining seconds = %d, want 1", code.RemainingSeconds)
	}

	if !code.ExpiresAt.Equal(time.Unix(60, 0)) {
		t.Fatalf("expires at = %s, want unix 60", code.ExpiresAt)
	}
}

func TestMaskSecret(t *testing.T) {
	if got := MaskSecret(" abcd efgh ijkl "); got != "ABCD****IJKL" {
		t.Fatalf("MaskSecret() = %q, want ABCD****IJKL", got)
	}

	if got := MaskSecret("ABC123"); got != "********" {
		t.Fatalf("MaskSecret() = %q, want ********", got)
	}
}

func TestGenerateTOTPWrapsInvalidBase32Error(t *testing.T) {
	_, err := GenerateTOTP(GenerateInput{
		Secret:        "NOT@BASE32",
		Algorithm:     AlgorithmSHA1,
		Digits:        6,
		PeriodSeconds: 30,
		Now:           time.Unix(59, 0),
	})
	if err == nil {
		t.Fatalf("GenerateTOTP() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "decode otp secret") {
		t.Fatalf("GenerateTOTP() error = %v, want decode otp secret", err)
	}

	var corruptInputError base32.CorruptInputError
	if !errors.As(err, &corruptInputError) {
		t.Fatalf("GenerateTOTP() error = %v, want CorruptInputError", err)
	}
}

func base32Secret(value string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(value))
}
