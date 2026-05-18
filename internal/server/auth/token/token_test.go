package token

import (
	"errors"
	"testing"
	"time"
)

func fixedNow() time.Time {
	return time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
}

func TestIssuerIssueCreatesTokenWithTTL(t *testing.T) {
	issuer := NewIssuerWithClock("test-secret", 5*time.Minute, fixedNow)

	accessToken, err := issuer.Issue("user-id-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if accessToken.Value == "" {
		t.Fatalf("access token value is empty")
	}

	if !accessToken.ExpiresAt.Equal(fixedNow().Add(5 * time.Minute)) {
		t.Fatalf("ExpiresAt = %s, want %s", accessToken.ExpiresAt, fixedNow().Add(5*time.Minute))
	}
}

func TestIssuerValidateReturnsClaimsForIssuedToken(t *testing.T) {
	issuer := NewIssuerWithClock("test-secret", 5*time.Minute, fixedNow)

	accessToken, err := issuer.Issue("user-id-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	claims, err := issuer.Validate(accessToken.Value)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if claims.UserID != "user-id-1" {
		t.Fatalf("UserID = %q, want %q", claims.UserID, "user-id-1")
	}

	if !claims.ExpiresAt.Equal(accessToken.ExpiresAt) {
		t.Fatalf("ExpiresAt = %s, want %s", claims.ExpiresAt, accessToken.ExpiresAt)
	}
}

func TestIssuerValidateRejectsTokenSignedWithAnotherSecret(t *testing.T) {
	issuer := NewIssuerWithClock("test-secret", 5*time.Minute, fixedNow)
	validator := NewIssuerWithClock("another-secret", 5*time.Minute, fixedNow)

	accessToken, err := issuer.Issue("user-id-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	_, err = validator.Validate(accessToken.Value)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Validate() error = %v, want ErrInvalidToken", err)
	}
}

func TestIssuerValidateRejectsExpiredToken(t *testing.T) {
	now := fixedNow()
	issuer := NewIssuerWithClock("test-secret", 5*time.Minute, func() time.Time {
		return now
	})

	accessToken, err := issuer.Issue("user-id-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	issuer = NewIssuerWithClock("test-secret", 5*time.Minute, func() time.Time {
		return now.Add(6 * time.Minute)
	})

	_, err = issuer.Validate(accessToken.Value)
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("Validate() error = %v, want ErrExpiredToken", err)
	}
}

func TestIssuerIssueReturnsErrorForInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		ttl    time.Duration
	}{
		{
			name:   "empty secret",
			secret: "",
			ttl:    5 * time.Minute,
		},
		{
			name:   "zero ttl",
			secret: "test-secret",
			ttl:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := NewIssuerWithClock(tt.secret, tt.ttl, fixedNow)

			_, err := issuer.Issue("user-id-1")
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Issue() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestIssuerIssueReturnsErrorForEmptyUserID(t *testing.T) {
	issuer := NewIssuerWithClock("test-secret", 5*time.Minute, fixedNow)

	_, err := issuer.Issue("")
	if !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("Issue() error = %v, want ErrInvalidClaims", err)
	}
}

func TestIssuerValidateRejectsEmptyToken(t *testing.T) {
	issuer := NewIssuerWithClock("test-secret", 5*time.Minute, fixedNow)

	_, err := issuer.Validate("")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Validate() error = %v, want ErrInvalidToken", err)
	}
}
