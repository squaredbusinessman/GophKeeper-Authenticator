package core

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestCurrentOTPCodeGeneratesCodeFromPayload(t *testing.T) {
	code, err := CurrentOTPCode(OTPPayload{
		Secret:    base32Secret("12345678901234567890"),
		Algorithm: "sha1",
		Digits:    6,
	}, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("CurrentOTPCode() error = %v", err)
	}

	if code.Value != "287082" {
		t.Fatalf("code = %q, want 287082", code.Value)
	}

	if code.PeriodSeconds != DefaultOTPPeriodSeconds {
		t.Fatalf("period seconds = %d, want %d", code.PeriodSeconds, DefaultOTPPeriodSeconds)
	}

	if code.RemainingSeconds != 1 {
		t.Fatalf("remaining seconds = %d, want 1", code.RemainingSeconds)
	}
}

func TestCurrentOTPCodeRejectsInvalidBase32Secret(t *testing.T) {
	_, err := CurrentOTPCode(OTPPayload{
		Secret:    "NOT@BASE32",
		Algorithm: "SHA1",
		Digits:    6,
	}, time.Unix(59, 0))
	if err == nil {
		t.Fatalf("CurrentOTPCode() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "decode otp secret") {
		t.Fatalf("CurrentOTPCode() error = %v, want decode otp secret", err)
	}
}

func TestMaskOTPSecret(t *testing.T) {
	if got := MaskOTPSecret(" abcd efgh ijkl "); got != "ABCD****IJKL" {
		t.Fatalf("MaskOTPSecret() = %q, want ABCD****IJKL", got)
	}
}

func base32Secret(value string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(value))
}
