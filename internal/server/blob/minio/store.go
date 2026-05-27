// Package minio адаптирует официальный MinIO Go SDK к blob.ObjectStore
package minio

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/blob"
)

// Config содержит настройки подключения к MinIO
type Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// Store сохраняет encrypted blob chunks в MinIO
type Store struct {
	client *minio.Client
	bucket string
}

// NewStore создает MinIO object storage
func NewStore(cfg Config) (*Store, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, fmt.Errorf("minio endpoint is required")
	}

	if strings.TrimSpace(cfg.AccessKey) == "" {
		return nil, fmt.Errorf("minio access key is required")
	}

	if strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, fmt.Errorf("minio secret key is required")
	}

	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, fmt.Errorf("minio bucket is required")
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}

	return &Store{
		client: client,
		bucket: cfg.Bucket,
	}, nil
}

// EnsureBucket проверяет наличие bucket и создает его при необходимости
func (s *Store) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("check minio bucket: %w", err)
	}

	if exists {
		return nil
	}

	if err = s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{}); err != nil {
		return fmt.Errorf("create minio bucket: %w", err)
	}

	return nil
}

// PutObject сохраняет encrypted object в MinIO
func (s *Store) PutObject(ctx context.Context, input blob.PutObjectInput) error {
	key := strings.TrimSpace(input.Key)
	if key == "" {
		return fmt.Errorf("object key is required")
	}

	if input.Reader == nil {
		return fmt.Errorf("object reader is required")
	}

	if input.Size <= 0 {
		return fmt.Errorf("object size must be greater than zero")
	}

	_, err := s.client.PutObject(ctx, s.bucket, key, input.Reader, input.Size, minio.PutObjectOptions{
		ContentType: input.ContentType,
	})
	if err != nil {
		return fmt.Errorf("put minio object: %w", err)
	}

	return nil
}

// GetObject открывает encrypted object для чтения
func (s *Store) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("object key is required")
	}

	object, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get minio object: %w", err)
	}

	return object, nil
}

// StatObject возвращает metadata encrypted object
func (s *Store) StatObject(ctx context.Context, key string) (blob.ObjectInfo, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return blob.ObjectInfo{}, fmt.Errorf("object key is required")
	}

	info, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return blob.ObjectInfo{}, fmt.Errorf("stat minio object: %w", err)
	}

	return blob.ObjectInfo{
		Key:  key,
		Size: info.Size,
	}, nil
}

// RemoveObject удаляет encrypted object из MinIO
func (s *Store) RemoveObject(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("object key is required")
	}

	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("remove minio object: %w", err)
	}

	return nil
}
