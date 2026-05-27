package core

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"google.golang.org/grpc"
)

// BlobServiceClient описывает gRPC-клиент blob API, который нужен client core
type BlobServiceClient interface {
	CreateBlobUpload(context.Context, *gophkeeperv1.CreateBlobUploadRequest, ...grpc.CallOption) (*gophkeeperv1.CreateBlobUploadResponse, error)
	UploadBlob(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[gophkeeperv1.UploadBlobChunkRequest, gophkeeperv1.UploadBlobResponse], error)
	DownloadBlob(context.Context, *gophkeeperv1.DownloadBlobRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[gophkeeperv1.DownloadBlobChunk], error)
	AbortBlobUpload(context.Context, *gophkeeperv1.AbortBlobUploadRequest, ...grpc.CallOption) (*gophkeeperv1.AbortBlobUploadResponse, error)
}

// CreateBlobUploadInput содержит параметры новой upload session
type CreateBlobUploadInput struct {
	ExpectedSize   int64
	ChunkSize      int64
	ExpectedChunks int32
	ChecksumSHA256 string
}

// BlobUpload содержит данные созданной upload session
type BlobUpload struct {
	ID        string
	ExpiresAt time.Time
	ChunkSize int64
}

// BlobChunk содержит encrypted chunk binary объекта
type BlobChunk struct {
	Index          int32
	Data           []byte
	ChecksumSHA256 string
}

// UploadBlobInput содержит chunks для завершения upload session
type UploadBlobInput struct {
	UploadID string
	Chunks   []BlobChunk
}

// UploadedBlob содержит metadata сохраненного blob
type UploadedBlob struct {
	ID             string
	StorageBucket  string
	ObjectPrefix   string
	ChunkSize      int64
	ChunkCount     int32
	SizeBytes      int64
	ChecksumSHA256 string
}

// DownloadBlobInput содержит параметры скачивания blob
type DownloadBlobInput struct {
	BlobID string
}

// DownloadBlobResult содержит скачанные encrypted chunks
type DownloadBlobResult struct {
	BlobID string
	Chunks []BlobChunk
}

// AbortBlobUploadInput содержит параметры отмены upload session
type AbortBlobUploadInput struct {
	UploadID string
}

// BlobService выполняет client blob flow без UI-логики
type BlobService struct {
	blobClient BlobServiceClient
}

// NewBlobService создает client blob core
func NewBlobService(blobClient BlobServiceClient) *BlobService {
	return &BlobService{
		blobClient: blobClient,
	}
}

// CreateUpload создает upload session для encrypted binary объекта
func (s *BlobService) CreateUpload(ctx context.Context, session Session, input CreateBlobUploadInput) (BlobUpload, error) {
	if err := s.validateDependencies(); err != nil {
		return BlobUpload{}, err
	}

	if err := validateSession(session); err != nil {
		return BlobUpload{}, err
	}

	if err := input.validate(); err != nil {
		return BlobUpload{}, err
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	response, err := s.blobClient.CreateBlobUpload(ctx, &gophkeeperv1.CreateBlobUploadRequest{
		ExpectedSize:   input.ExpectedSize,
		ChunkSize:      input.ChunkSize,
		ExpectedChunks: input.ExpectedChunks,
		ChecksumSha256: input.ChecksumSHA256,
	})
	if err != nil {
		return BlobUpload{}, fmt.Errorf("create blob upload: %w", err)
	}

	return BlobUpload{
		ID:        response.GetUploadId(),
		ExpiresAt: timestampToTime(response.GetExpiresAt()),
		ChunkSize: response.GetChunkSize(),
	}, nil
}

// Upload отправляет encrypted chunks и получает metadata готового blob
func (s *BlobService) Upload(ctx context.Context, session Session, input UploadBlobInput) (UploadedBlob, error) {
	if err := s.validateDependencies(); err != nil {
		return UploadedBlob{}, err
	}

	if err := validateSession(session); err != nil {
		return UploadedBlob{}, err
	}

	if err := input.validate(); err != nil {
		return UploadedBlob{}, err
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	stream, err := s.blobClient.UploadBlob(ctx)
	if err != nil {
		return UploadedBlob{}, fmt.Errorf("open blob upload stream: %w", err)
	}

	for _, chunk := range input.Chunks {
		if err = chunk.validate(); err != nil {
			return UploadedBlob{}, err
		}

		if err = stream.Send(&gophkeeperv1.UploadBlobChunkRequest{
			UploadId:       input.UploadID,
			ChunkIndex:     chunk.Index,
			Data:           chunk.Data,
			ChecksumSha256: chunk.ChecksumSHA256,
		}); err != nil {
			return UploadedBlob{}, fmt.Errorf("send blob chunk: %w", err)
		}
	}

	response, err := stream.CloseAndRecv()
	if err != nil {
		return UploadedBlob{}, fmt.Errorf("finish blob upload: %w", err)
	}

	return uploadedBlobFromProto(response), nil
}

// Download скачивает encrypted chunks blob
func (s *BlobService) Download(ctx context.Context, session Session, input DownloadBlobInput) (DownloadBlobResult, error) {
	if err := s.validateDependencies(); err != nil {
		return DownloadBlobResult{}, err
	}

	if err := validateSession(session); err != nil {
		return DownloadBlobResult{}, err
	}

	if err := input.validate(); err != nil {
		return DownloadBlobResult{}, err
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	stream, err := s.blobClient.DownloadBlob(ctx, &gophkeeperv1.DownloadBlobRequest{
		BlobId: strings.TrimSpace(input.BlobID),
	})
	if err != nil {
		return DownloadBlobResult{}, fmt.Errorf("open blob download stream: %w", err)
	}

	result := DownloadBlobResult{
		BlobID: strings.TrimSpace(input.BlobID),
	}

	for {
		chunk, err := stream.Recv()
		if err == nil {
			result.Chunks = append(result.Chunks, BlobChunk{
				Index:          chunk.GetChunkIndex(),
				Data:           chunk.GetData(),
				ChecksumSHA256: chunk.GetChecksumSha256(),
			})
			continue
		}

		if err == io.EOF {
			break
		}

		return DownloadBlobResult{}, fmt.Errorf("receive blob chunk: %w", err)
	}

	return result, nil
}

// AbortUpload отменяет upload session
func (s *BlobService) AbortUpload(ctx context.Context, session Session, input AbortBlobUploadInput) error {
	if err := s.validateDependencies(); err != nil {
		return err
	}

	if err := validateSession(session); err != nil {
		return err
	}

	if err := input.validate(); err != nil {
		return err
	}

	ctx = contextWithAccessToken(ctx, session.AccessToken)

	if _, err := s.blobClient.AbortBlobUpload(ctx, &gophkeeperv1.AbortBlobUploadRequest{
		UploadId: strings.TrimSpace(input.UploadID),
	}); err != nil {
		return fmt.Errorf("abort blob upload: %w", err)
	}

	return nil
}

func (s *BlobService) validateDependencies() error {
	if s.blobClient == nil {
		return fmt.Errorf("blob client is required")
	}

	return nil
}

func (i *CreateBlobUploadInput) validate() error {
	if i.ExpectedSize <= 0 {
		return fmt.Errorf("expected size must be greater than zero")
	}

	if i.ExpectedChunks <= 0 {
		return fmt.Errorf("expected chunks must be greater than zero")
	}

	if strings.TrimSpace(i.ChecksumSHA256) == "" {
		return fmt.Errorf("checksum sha256 is required")
	}

	return nil
}

func (i *UploadBlobInput) validate() error {
	if strings.TrimSpace(i.UploadID) == "" {
		return fmt.Errorf("upload id is required")
	}

	if len(i.Chunks) == 0 {
		return fmt.Errorf("at least one blob chunk is required")
	}

	return nil
}

func (c *BlobChunk) validate() error {
	if c.Index < 0 {
		return fmt.Errorf("chunk index must not be negative")
	}

	if len(c.Data) == 0 {
		return fmt.Errorf("chunk data is required")
	}

	if strings.TrimSpace(c.ChecksumSHA256) == "" {
		return fmt.Errorf("chunk checksum sha256 is required")
	}

	return nil
}

func (i *DownloadBlobInput) validate() error {
	if strings.TrimSpace(i.BlobID) == "" {
		return fmt.Errorf("blob id is required")
	}

	return nil
}

func (i *AbortBlobUploadInput) validate() error {
	if strings.TrimSpace(i.UploadID) == "" {
		return fmt.Errorf("upload id is required")
	}

	return nil
}

func uploadedBlobFromProto(response *gophkeeperv1.UploadBlobResponse) UploadedBlob {
	if response == nil {
		return UploadedBlob{}
	}

	return UploadedBlob{
		ID:             response.GetBlobId(),
		StorageBucket:  response.GetStorageBucket(),
		ObjectPrefix:   response.GetObjectPrefix(),
		ChunkSize:      response.GetChunkSize(),
		ChunkCount:     response.GetChunkCount(),
		SizeBytes:      response.GetSizeBytes(),
		ChecksumSHA256: response.GetChecksumSha256(),
	}
}
