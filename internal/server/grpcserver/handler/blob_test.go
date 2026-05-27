package handler

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/blob"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver/authcontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeBlobUseCase struct {
	createUploadFunc func(context.Context, blob.CreateUploadInput) (blob.Upload, error)
	uploadChunkFunc  func(context.Context, blob.UploadChunkInput) error
	commitUploadFunc func(context.Context, blob.CommitUploadInput) (blob.Blob, error)
	abortUploadFunc  func(context.Context, blob.AbortUploadInput) error
	downloadBlobFunc func(context.Context, blob.DownloadBlobInput) (blob.DownloadBlobResult, error)
	openObjectFunc   func(context.Context, string) (io.ReadCloser, error)
}

func (u *fakeBlobUseCase) CreateUpload(ctx context.Context, input blob.CreateUploadInput) (blob.Upload, error) {
	if u.createUploadFunc != nil {
		return u.createUploadFunc(ctx, input)
	}

	return blob.Upload{}, errors.New("unexpected create upload call")
}

func (u *fakeBlobUseCase) UploadChunk(ctx context.Context, input blob.UploadChunkInput) error {
	if u.uploadChunkFunc != nil {
		return u.uploadChunkFunc(ctx, input)
	}

	return errors.New("unexpected upload chunk call")
}

func (u *fakeBlobUseCase) CommitUpload(ctx context.Context, input blob.CommitUploadInput) (blob.Blob, error) {
	if u.commitUploadFunc != nil {
		return u.commitUploadFunc(ctx, input)
	}

	return blob.Blob{}, errors.New("unexpected commit upload call")
}

func (u *fakeBlobUseCase) AbortUpload(ctx context.Context, input blob.AbortUploadInput) error {
	if u.abortUploadFunc != nil {
		return u.abortUploadFunc(ctx, input)
	}

	return errors.New("unexpected abort upload call")
}

func (u *fakeBlobUseCase) DownloadBlob(ctx context.Context, input blob.DownloadBlobInput) (blob.DownloadBlobResult, error) {
	if u.downloadBlobFunc != nil {
		return u.downloadBlobFunc(ctx, input)
	}

	return blob.DownloadBlobResult{}, errors.New("unexpected download blob call")
}

func (u *fakeBlobUseCase) OpenObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if u.openObjectFunc != nil {
		return u.openObjectFunc(ctx, key)
	}

	return nil, errors.New("unexpected open object call")
}

func TestBlobHandlerCreateBlobUpload(t *testing.T) {
	expiresAt := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	useCase := &fakeBlobUseCase{
		createUploadFunc: func(_ context.Context, input blob.CreateUploadInput) (blob.Upload, error) {
			if input.UserID != "user-id" {
				t.Fatalf("user id = %q, want user-id", input.UserID)
			}
			if input.ExpectedSize != 12 {
				t.Fatalf("expected size = %d, want 12", input.ExpectedSize)
			}
			if input.ExpectedChunks != 2 {
				t.Fatalf("expected chunks = %d, want 2", input.ExpectedChunks)
			}
			if input.ChecksumSHA256 != "blob-checksum" {
				t.Fatalf("checksum = %q, want blob-checksum", input.ChecksumSHA256)
			}

			return blob.Upload{
				ID:        "upload-id",
				ChunkSize: 6,
				ExpiresAt: expiresAt,
			}, nil
		},
	}
	handler := NewBlobHandler(useCase)
	ctx := authcontext.ContextWithUserID(context.Background(), "user-id")

	response, err := handler.CreateBlobUpload(ctx, &gophkeeperv1.CreateBlobUploadRequest{
		ExpectedSize:   12,
		ExpectedChunks: 2,
		ChecksumSha256: "blob-checksum",
	})
	if err != nil {
		t.Fatalf("CreateBlobUpload() error = %v", err)
	}

	if response.GetUploadId() != "upload-id" {
		t.Fatalf("upload id = %q, want upload-id", response.GetUploadId())
	}
	if response.GetChunkSize() != 6 {
		t.Fatalf("chunk size = %d, want 6", response.GetChunkSize())
	}
	if !response.GetExpiresAt().AsTime().Equal(expiresAt) {
		t.Fatalf("expires at = %s, want %s", response.GetExpiresAt().AsTime(), expiresAt)
	}
}

func TestBlobHandlerAbortBlobUploadMapsError(t *testing.T) {
	useCase := &fakeBlobUseCase{
		abortUploadFunc: func(_ context.Context, input blob.AbortUploadInput) error {
			if input.UserID != "user-id" {
				t.Fatalf("user id = %q, want user-id", input.UserID)
			}
			if input.UploadID != "upload-id" {
				t.Fatalf("upload id = %q, want upload-id", input.UploadID)
			}

			return blob.ErrUploadNotFound
		},
	}
	handler := NewBlobHandler(useCase)
	ctx := authcontext.ContextWithUserID(context.Background(), "user-id")

	_, err := handler.AbortBlobUpload(ctx, &gophkeeperv1.AbortBlobUploadRequest{
		UploadId: "upload-id",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %s, want NotFound", status.Code(err))
	}
}

func TestBlobStatusError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "invalid input", err: blob.ErrInvalidInput, code: codes.InvalidArgument},
		{name: "upload not found", err: blob.ErrUploadNotFound, code: codes.NotFound},
		{name: "blob not found", err: blob.ErrBlobNotFound, code: codes.NotFound},
		{name: "access denied", err: blob.ErrAccessDenied, code: codes.PermissionDenied},
		{name: "upload expired", err: blob.ErrUploadExpired, code: codes.FailedPrecondition},
		{name: "upload incomplete", err: blob.ErrUploadIncomplete, code: codes.FailedPrecondition},
		{name: "unknown", err: errors.New("boom"), code: codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := blobStatusError(tt.err)
			if status.Code(err) != tt.code {
				t.Fatalf("code = %s, want %s", status.Code(err), tt.code)
			}
		})
	}
}

func TestBlobToUploadResponse(t *testing.T) {
	response := blobToUploadResponse(blob.Blob{
		ID:             "blob-id",
		StorageBucket:  "bucket",
		ObjectPrefix:   "prefix",
		ChunkSize:      4,
		ChunkCount:     2,
		SizeBytes:      8,
		ChecksumSHA256: "blob-checksum",
	})

	if response.GetBlobId() != "blob-id" {
		t.Fatalf("blob id = %q, want blob-id", response.GetBlobId())
	}
	if response.GetChecksumSha256() != "blob-checksum" {
		t.Fatalf("checksum = %q, want blob-checksum", response.GetChecksumSha256())
	}
}
