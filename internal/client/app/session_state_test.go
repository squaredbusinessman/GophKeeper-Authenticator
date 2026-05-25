package app

import (
	"bytes"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
)

func TestSessionStateStoresAndClearsSession(t *testing.T) {
	state := NewSessionState()

	if _, ok := state.Session(); ok {
		t.Fatalf("Session() ok = true, want false")
	}

	session := core.Session{
		AccessToken:          "access-token",
		AccessTokenExpiresAt: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
		VaultKey:             bytes.Repeat([]byte{1}, 32),
	}
	if err := state.SetSession(session); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	got, ok := state.Session()
	if !ok {
		t.Fatalf("Session() ok = false, want true")
	}

	if got.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want access-token", got.AccessToken)
	}

	state.Clear()

	if _, ok = state.Session(); ok {
		t.Fatalf("Session() ok after Clear = true, want false")
	}
}

func TestSessionStateRejectsInvalidSession(t *testing.T) {
	state := NewSessionState()

	if err := state.SetSession(core.Session{VaultKey: bytes.Repeat([]byte{1}, 32)}); err == nil {
		t.Fatalf("SetSession() error = nil, want access token error")
	}

	if err := state.SetSession(core.Session{AccessToken: "access-token"}); err == nil {
		t.Fatalf("SetSession() error = nil, want vault key error")
	}
}

func TestSessionStateNilReceiver(t *testing.T) {
	var state *SessionState

	if err := state.SetSession(core.Session{AccessToken: "access-token", VaultKey: bytes.Repeat([]byte{1}, 32)}); err == nil {
		t.Fatalf("SetSession() error = nil, want error")
	}

	if _, ok := state.Session(); ok {
		t.Fatalf("Session() ok = true, want false")
	}

	state.Clear()
}
