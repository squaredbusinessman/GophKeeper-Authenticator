package logger

import "testing"

func TestNewCreatesLoggerForSupportedModes(t *testing.T) {
	for _, mode := range []string{"dev", "prod"} {
		log, err := New(mode)
		if err != nil {
			t.Fatalf("New(%q) error = %v", mode, err)
		}

		if log == nil {
			t.Fatalf("New(%q) logger = nil", mode)
		}

		_ = log.Sync()
	}
}

func TestNewReturnsErrorForUnsupportedMode(t *testing.T) {
	_, err := New("pretty")
	if err == nil {
		t.Fatalf("New() error = nil, want error")
	}
}
