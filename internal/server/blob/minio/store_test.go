package minio

import (
	"strings"
	"testing"
)

func TestNewStoreValidatesConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "missing endpoint",
			cfg: Config{
				AccessKey: "access",
				SecretKey: "secret",
				Bucket:    "bucket",
			},
			wantErr: "endpoint",
		},
		{
			name: "missing access key",
			cfg: Config{
				Endpoint:  "localhost:9000",
				SecretKey: "secret",
				Bucket:    "bucket",
			},
			wantErr: "access key",
		},
		{
			name: "missing secret key",
			cfg: Config{
				Endpoint:  "localhost:9000",
				AccessKey: "access",
				Bucket:    "bucket",
			},
			wantErr: "secret key",
		},
		{
			name: "missing bucket",
			cfg: Config{
				Endpoint:  "localhost:9000",
				AccessKey: "access",
				SecretKey: "secret",
			},
			wantErr: "bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStore(tt.cfg)
			if err == nil {
				t.Fatalf("NewStore() error = nil, want error")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewStore() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestNewStoreCreatesStore(t *testing.T) {
	store, err := NewStore(Config{
		Endpoint:  "localhost:9000",
		AccessKey: "access",
		SecretKey: "secret",
		Bucket:    "bucket",
	})
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	if store == nil {
		t.Fatalf("NewStore() = nil, want store")
	}
}
