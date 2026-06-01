package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	// ErrInvalidInput означает некорректные входные данные blob use case
	ErrInvalidInput = errors.New("invalid blob input")

	// ErrUploadNotFound означает, что upload session не найдена
	ErrUploadNotFound = errors.New("blob upload not found")

	// ErrBlobNotFound означает, что blob не найден
	ErrBlobNotFound = errors.New("blob not found")

	// ErrAccessDenied означает попытку доступа к blob другого пользователя
	ErrAccessDenied = errors.New("blob access denied")

	// ErrUploadExpired означает, что upload session истекла
	ErrUploadExpired = errors.New("blob upload expired")

	// ErrUploadIncomplete означает, что upload session содержит не все chunks
	ErrUploadIncomplete = errors.New("blob upload incomplete")
)

const (
	// UploadStatusCreated означает созданную upload session
	UploadStatusCreated = "created"

	// UploadStatusUploading означает upload session в процессе загрузки
	UploadStatusUploading = "uploading"

	// UploadStatusCommitted означает завершенную upload session
	UploadStatusCommitted = "committed"

	// UploadStatusAborted означает отмененную upload session
	UploadStatusAborted = "aborted"

	// UploadStatusExpired означает истекшую upload session
	UploadStatusExpired = "expired"

	// BlobStatusReady означает готовый blob
	BlobStatusReady = "ready"
)

// IDGenerator генерирует UUID для blob metadata
type IDGenerator interface {
	NewID() (string, error)
}

// Repository сохраняет metadata blob upload sessions
type Repository interface {
	CreateUpload(context.Context, CreateUploadParams) (Upload, error)
	FindUploadByID(context.Context, string) (Upload, error)
	AddUploadPart(context.Context, AddUploadPartParams) error
	ListUploadParts(context.Context, string) ([]UploadPart, error)
	CommitUpload(context.Context, CommitUploadParams) (Blob, error)
	AbortUpload(context.Context, AbortUploadParams) error
	FindBlobByID(context.Context, string) (Blob, error)
}

// Service выполняет use case encrypted blob storage
type Service struct {
	repository  Repository
	objectStore ObjectStore
	idGenerator IDGenerator
	bucket      string
	chunkSize   int64
	maxSize     int64
	uploadTTL   time.Duration
	now         func() time.Time
}

// Config содержит настройки blob use case
type Config struct {
	Bucket    string
	ChunkSize int64
	MaxSize   int64
	UploadTTL time.Duration
	Now       func() time.Time
}

// Upload содержит upload session
type Upload struct {
	ID             string
	UserID         string
	Status         string
	ChunkSize      int64
	ExpectedSize   int64
	ExpectedChunks int32
	ReceivedChunks int32
	ChecksumSHA256 string
	ExpiresAt      time.Time
}

// UploadPart содержит metadata загруженного chunk
type UploadPart struct {
	UploadID       string
	ChunkIndex     int32
	ObjectKey      string
	SizeBytes      int64
	ChecksumSHA256 string
}

// Blob содержит metadata сохраненного encrypted blob
type Blob struct {
	ID             string
	UserID         string
	UploadID       string
	Status         string
	StorageBucket  string
	ObjectPrefix   string
	ChunkSize      int64
	ChunkCount     int32
	SizeBytes      int64
	ChecksumSHA256 string
}

// CreateUploadInput содержит параметры создания upload session
type CreateUploadInput struct {
	UserID         string
	ExpectedSize   int64
	ChunkSize      int64
	ExpectedChunks int32
	ChecksumSHA256 string
}

// UploadChunkInput содержит encrypted chunk для сохранения
type UploadChunkInput struct {
	UserID         string
	UploadID       string
	ChunkIndex     int32
	Data           []byte
	ChecksumSHA256 string
}

// CommitUploadInput содержит параметры завершения upload session
type CommitUploadInput struct {
	UserID   string
	UploadID string
}

// AbortUploadInput содержит параметры отмены upload session
type AbortUploadInput struct {
	UserID   string
	UploadID string
}

// DownloadBlobInput содержит параметры скачивания blob
type DownloadBlobInput struct {
	UserID string
	BlobID string
}

// DownloadBlobResult содержит blob metadata и его chunks
type DownloadBlobResult struct {
	Blob  Blob
	Parts []UploadPart
}

// CreateUploadParams содержит данные repository для upload session
type CreateUploadParams struct {
	UploadID       string
	UserID         string
	Status         string
	ChunkSize      int64
	ExpectedSize   int64
	ExpectedChunks int32
	ChecksumSHA256 string
	ExpiresAt      time.Time
}

// AddUploadPartParams содержит данные repository для chunk metadata
type AddUploadPartParams struct {
	UploadID       string
	ChunkIndex     int32
	ObjectKey      string
	SizeBytes      int64
	ChecksumSHA256 string
}

// CommitUploadParams содержит данные repository для commit upload
type CommitUploadParams struct {
	UploadID       string
	UserID         string
	BlobID         string
	StorageBucket  string
	ObjectPrefix   string
	ChecksumSHA256 string
}

// AbortUploadParams содержит данные repository для abort upload
type AbortUploadParams struct {
	UploadID string
	UserID   string
}

// NewService создает blob use case
func NewService(repository Repository, objectStore ObjectStore, idGenerator IDGenerator, cfg Config) *Service {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		repository:  repository,
		objectStore: objectStore,
		idGenerator: idGenerator,
		bucket:      cfg.Bucket,
		chunkSize:   cfg.ChunkSize,
		maxSize:     cfg.MaxSize,
		uploadTTL:   cfg.UploadTTL,
		now:         now,
	}
}

// CreateUpload создает upload session
func (s *Service) CreateUpload(ctx context.Context, input CreateUploadInput) (Upload, error) {
	if err := s.validateDependencies(); err != nil {
		return Upload{}, err
	}

	if strings.TrimSpace(input.UserID) == "" {
		return Upload{}, fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if input.ExpectedSize <= 0 {
		return Upload{}, fmt.Errorf("%w: expected size must be greater than zero", ErrInvalidInput)
	}

	if s.maxSize > 0 && input.ExpectedSize > s.maxSize {
		return Upload{}, fmt.Errorf("%w: expected size exceeds blob max size", ErrInvalidInput)
	}

	chunkSize := input.ChunkSize
	if chunkSize <= 0 {
		chunkSize = s.chunkSize
	}

	if chunkSize <= 0 {
		return Upload{}, fmt.Errorf("%w: chunk size must be greater than zero", ErrInvalidInput)
	}

	if input.ExpectedChunks <= 0 {
		return Upload{}, fmt.Errorf("%w: expected chunks must be greater than zero", ErrInvalidInput)
	}

	if strings.TrimSpace(input.ChecksumSHA256) == "" {
		return Upload{}, fmt.Errorf("%w: checksum sha256 is required", ErrInvalidInput)
	}

	uploadID, err := s.idGenerator.NewID()
	if err != nil {
		return Upload{}, fmt.Errorf("generate upload id: %w", err)
	}

	return s.repository.CreateUpload(ctx, CreateUploadParams{
		UploadID:       uploadID,
		UserID:         input.UserID,
		Status:         UploadStatusCreated,
		ChunkSize:      chunkSize,
		ExpectedSize:   input.ExpectedSize,
		ExpectedChunks: input.ExpectedChunks,
		ChecksumSHA256: input.ChecksumSHA256,
		ExpiresAt:      s.now().Add(s.uploadTTL).UTC(),
	})
}

// UploadChunk сохраняет encrypted chunk в object storage и metadata в БД
func (s *Service) UploadChunk(ctx context.Context, input UploadChunkInput) error {
	if err := s.validateDependencies(); err != nil {
		return err
	}

	if strings.TrimSpace(input.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if strings.TrimSpace(input.UploadID) == "" {
		return fmt.Errorf("%w: upload id is required", ErrInvalidInput)
	}

	if input.ChunkIndex < 0 {
		return fmt.Errorf("%w: chunk index must not be negative", ErrInvalidInput)
	}

	if len(input.Data) == 0 {
		return fmt.Errorf("%w: chunk data is required", ErrInvalidInput)
	}

	if strings.TrimSpace(input.ChecksumSHA256) == "" {
		return fmt.Errorf("%w: chunk checksum sha256 is required", ErrInvalidInput)
	}

	upload, err := s.repository.FindUploadByID(ctx, input.UploadID)
	if err != nil {
		return err
	}

	if upload.UserID != input.UserID {
		return ErrAccessDenied
	}

	if upload.Status == UploadStatusCommitted || upload.Status == UploadStatusAborted {
		return fmt.Errorf("%w: upload is not writable", ErrInvalidInput)
	}

	if !upload.ExpiresAt.IsZero() && s.now().After(upload.ExpiresAt) {
		return ErrUploadExpired
	}

	if int64(len(input.Data)) > upload.ChunkSize {
		return fmt.Errorf("%w: chunk data exceeds upload chunk size", ErrInvalidInput)
	}

	objectKey := uploadChunkObjectKey(input.UserID, input.UploadID, input.ChunkIndex)
	if err = s.objectStore.PutObject(ctx, PutObjectInput{
		Key:         objectKey,
		Reader:      bytes.NewReader(input.Data),
		Size:        int64(len(input.Data)),
		ContentType: "application/octet-stream",
	}); err != nil {
		return err
	}

	return s.repository.AddUploadPart(ctx, AddUploadPartParams{
		UploadID:       input.UploadID,
		ChunkIndex:     input.ChunkIndex,
		ObjectKey:      objectKey,
		SizeBytes:      int64(len(input.Data)),
		ChecksumSHA256: input.ChecksumSHA256,
	})
}

// CommitUpload завершает upload session и создает blob metadata
func (s *Service) CommitUpload(ctx context.Context, input CommitUploadInput) (Blob, error) {
	if err := s.validateDependencies(); err != nil {
		return Blob{}, err
	}

	if strings.TrimSpace(input.UserID) == "" {
		return Blob{}, fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if strings.TrimSpace(input.UploadID) == "" {
		return Blob{}, fmt.Errorf("%w: upload id is required", ErrInvalidInput)
	}

	upload, err := s.repository.FindUploadByID(ctx, input.UploadID)
	if err != nil {
		return Blob{}, err
	}

	if upload.UserID != input.UserID {
		return Blob{}, ErrAccessDenied
	}

	if !upload.ExpiresAt.IsZero() && s.now().After(upload.ExpiresAt) {
		return Blob{}, ErrUploadExpired
	}

	blobID, err := s.idGenerator.NewID()
	if err != nil {
		return Blob{}, fmt.Errorf("generate blob id: %w", err)
	}

	return s.repository.CommitUpload(ctx, CommitUploadParams{
		UploadID:       input.UploadID,
		UserID:         input.UserID,
		BlobID:         blobID,
		StorageBucket:  s.bucket,
		ObjectPrefix:   uploadObjectPrefix(input.UserID, input.UploadID),
		ChecksumSHA256: upload.ChecksumSHA256,
	})
}

// AbortUpload отменяет upload session и удаляет принятые chunks
func (s *Service) AbortUpload(ctx context.Context, input AbortUploadInput) error {
	if err := s.validateDependencies(); err != nil {
		return err
	}

	if strings.TrimSpace(input.UserID) == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if strings.TrimSpace(input.UploadID) == "" {
		return fmt.Errorf("%w: upload id is required", ErrInvalidInput)
	}

	upload, err := s.repository.FindUploadByID(ctx, input.UploadID)
	if err != nil {
		return err
	}

	if upload.UserID != input.UserID {
		return ErrAccessDenied
	}

	parts, err := s.repository.ListUploadParts(ctx, input.UploadID)
	if err != nil {
		return err
	}

	for _, part := range parts {
		if err = s.objectStore.RemoveObject(ctx, part.ObjectKey); err != nil {
			return err
		}
	}

	return s.repository.AbortUpload(ctx, AbortUploadParams{
		UploadID: input.UploadID,
		UserID:   input.UserID,
	})
}

// DownloadBlob возвращает metadata chunks для скачивания
func (s *Service) DownloadBlob(ctx context.Context, input DownloadBlobInput) (DownloadBlobResult, error) {
	if err := s.validateDependencies(); err != nil {
		return DownloadBlobResult{}, err
	}

	if strings.TrimSpace(input.UserID) == "" {
		return DownloadBlobResult{}, fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}

	if strings.TrimSpace(input.BlobID) == "" {
		return DownloadBlobResult{}, fmt.Errorf("%w: blob id is required", ErrInvalidInput)
	}

	blobItem, err := s.repository.FindBlobByID(ctx, input.BlobID)
	if err != nil {
		return DownloadBlobResult{}, err
	}

	if blobItem.UserID != input.UserID {
		return DownloadBlobResult{}, ErrAccessDenied
	}

	parts, err := s.repository.ListUploadParts(ctx, blobItem.UploadID)
	if err != nil {
		return DownloadBlobResult{}, err
	}

	return DownloadBlobResult{
		Blob:  blobItem,
		Parts: parts,
	}, nil
}

// OpenObject открывает encrypted chunk для чтения из object storage
func (s *Service) OpenObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := s.validateDependencies(); err != nil {
		return nil, err
	}

	return s.objectStore.GetObject(ctx, key)
}

func (s *Service) validateDependencies() error {
	if s.repository == nil {
		return fmt.Errorf("blob repository is required")
	}

	if s.objectStore == nil {
		return fmt.Errorf("blob object store is required")
	}

	if s.idGenerator == nil {
		return fmt.Errorf("blob id generator is required")
	}

	if strings.TrimSpace(s.bucket) == "" {
		return fmt.Errorf("blob bucket is required")
	}

	return nil
}

func uploadObjectPrefix(userID string, uploadID string) string {
	return "users/" + userID + "/uploads/" + uploadID
}

func uploadChunkObjectKey(userID string, uploadID string, chunkIndex int32) string {
	return fmt.Sprintf("%s/chunks/%d", uploadObjectPrefix(userID, uploadID), chunkIndex)
}
