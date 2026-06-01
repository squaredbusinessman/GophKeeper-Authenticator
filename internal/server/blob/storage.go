// Package blob содержит серверные типы для encrypted binary object storage
package blob

import (
	"context"
	"io"
)

// ObjectStore описывает storage для encrypted blob chunks
type ObjectStore interface {
	EnsureBucket(context.Context) error
	PutObject(context.Context, PutObjectInput) error
	GetObject(context.Context, string) (io.ReadCloser, error)
	StatObject(context.Context, string) (ObjectInfo, error)
	RemoveObject(context.Context, string) error
}

// PutObjectInput содержит данные encrypted object для сохранения
type PutObjectInput struct {
	Key         string
	Reader      io.Reader
	Size        int64
	ContentType string
}

// ObjectInfo содержит metadata object storage
type ObjectInfo struct {
	Key  string
	Size int64
}
