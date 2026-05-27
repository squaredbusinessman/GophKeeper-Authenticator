package handler

import (
	"context"
	"errors"
	"io"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/blob"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/grpcserver/authcontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BlobUseCase описывает use case для encrypted blob storage
type BlobUseCase interface {
	CreateUpload(context.Context, blob.CreateUploadInput) (blob.Upload, error)
	UploadChunk(context.Context, blob.UploadChunkInput) error
	CommitUpload(context.Context, blob.CommitUploadInput) (blob.Blob, error)
	AbortUpload(context.Context, blob.AbortUploadInput) error
	DownloadBlob(context.Context, blob.DownloadBlobInput) (blob.DownloadBlobResult, error)
	OpenObject(context.Context, string) (io.ReadCloser, error)
}

// BlobHandler обрабатывает gRPC-запросы encrypted blob storage
type BlobHandler struct {
	gophkeeperv1.UnimplementedBlobServiceServer

	blobUseCase BlobUseCase
}

// NewBlobHandler создает обработчик encrypted blob storage
func NewBlobHandler(blobUseCase BlobUseCase) *BlobHandler {
	return &BlobHandler{
		blobUseCase: blobUseCase,
	}
}

// CreateBlobUpload создает upload session для encrypted binary объекта
func (h *BlobHandler) CreateBlobUpload(ctx context.Context, req *gophkeeperv1.CreateBlobUploadRequest) (*gophkeeperv1.CreateBlobUploadResponse, error) {
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user id is required")
	}

	if h.blobUseCase == nil {
		return nil, status.Error(codes.Internal, "blob use case is not configured")
	}

	upload, err := h.blobUseCase.CreateUpload(ctx, blob.CreateUploadInput{
		UserID:         userID,
		ExpectedSize:   req.GetExpectedSize(),
		ChunkSize:      req.GetChunkSize(),
		ExpectedChunks: req.GetExpectedChunks(),
		ChecksumSHA256: req.GetChecksumSha256(),
	})
	if err != nil {
		return nil, blobStatusError(err)
	}

	return &gophkeeperv1.CreateBlobUploadResponse{
		UploadId:  upload.ID,
		ExpiresAt: timestamppb.New(upload.ExpiresAt),
		ChunkSize: upload.ChunkSize,
	}, nil
}

// UploadBlob принимает encrypted chunks и завершает upload session
func (h *BlobHandler) UploadBlob(stream gophkeeperv1.BlobService_UploadBlobServer) error {
	ctx := stream.Context()
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "user id is required")
	}

	if h.blobUseCase == nil {
		return status.Error(codes.Internal, "blob use case is not configured")
	}

	var uploadID string
	chunksReceived := 0

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return blobStatusError(err)
		}

		if uploadID == "" {
			uploadID = req.GetUploadId()
		}
		if req.GetUploadId() != uploadID {
			return status.Error(codes.InvalidArgument, "all chunks must use one upload id")
		}

		if err = h.blobUseCase.UploadChunk(ctx, blob.UploadChunkInput{
			UserID:         userID,
			UploadID:       req.GetUploadId(),
			ChunkIndex:     req.GetChunkIndex(),
			Data:           req.GetData(),
			ChecksumSHA256: req.GetChecksumSha256(),
		}); err != nil {
			return blobStatusError(err)
		}

		chunksReceived++
	}

	if chunksReceived == 0 {
		return status.Error(codes.InvalidArgument, "at least one chunk is required")
	}

	blobItem, err := h.blobUseCase.CommitUpload(ctx, blob.CommitUploadInput{
		UserID:   userID,
		UploadID: uploadID,
	})
	if err != nil {
		return blobStatusError(err)
	}

	return stream.SendAndClose(blobToUploadResponse(blobItem))
}

// DownloadBlob отправляет encrypted chunks через stream
func (h *BlobHandler) DownloadBlob(req *gophkeeperv1.DownloadBlobRequest, stream gophkeeperv1.BlobService_DownloadBlobServer) error {
	ctx := stream.Context()
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "user id is required")
	}

	if h.blobUseCase == nil {
		return status.Error(codes.Internal, "blob use case is not configured")
	}

	result, err := h.blobUseCase.DownloadBlob(ctx, blob.DownloadBlobInput{
		UserID: userID,
		BlobID: req.GetBlobId(),
	})
	if err != nil {
		return blobStatusError(err)
	}

	for _, part := range result.Parts {
		reader, err := h.blobUseCase.OpenObject(ctx, part.ObjectKey)
		if err != nil {
			return blobStatusError(err)
		}

		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			return blobStatusError(readErr)
		}
		if closeErr != nil {
			return blobStatusError(closeErr)
		}

		if err = stream.Send(&gophkeeperv1.DownloadBlobChunk{
			BlobId:         result.Blob.ID,
			ChunkIndex:     part.ChunkIndex,
			Data:           data,
			ChecksumSha256: part.ChecksumSHA256,
		}); err != nil {
			return blobStatusError(err)
		}
	}

	return nil
}

// AbortBlobUpload отменяет upload session
func (h *BlobHandler) AbortBlobUpload(ctx context.Context, req *gophkeeperv1.AbortBlobUploadRequest) (*gophkeeperv1.AbortBlobUploadResponse, error) {
	userID, ok := authcontext.UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user id is required")
	}

	if h.blobUseCase == nil {
		return nil, status.Error(codes.Internal, "blob use case is not configured")
	}

	if err := h.blobUseCase.AbortUpload(ctx, blob.AbortUploadInput{
		UserID:   userID,
		UploadID: req.GetUploadId(),
	}); err != nil {
		return nil, blobStatusError(err)
	}

	return &gophkeeperv1.AbortBlobUploadResponse{
		UploadId: req.GetUploadId(),
	}, nil
}

func blobToUploadResponse(blobItem blob.Blob) *gophkeeperv1.UploadBlobResponse {
	return &gophkeeperv1.UploadBlobResponse{
		BlobId:         blobItem.ID,
		StorageBucket:  blobItem.StorageBucket,
		ObjectPrefix:   blobItem.ObjectPrefix,
		ChunkSize:      blobItem.ChunkSize,
		ChunkCount:     blobItem.ChunkCount,
		SizeBytes:      blobItem.SizeBytes,
		ChecksumSha256: blobItem.ChecksumSHA256,
	}
}

func blobStatusError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, blob.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, blob.ErrUploadNotFound), errors.Is(err, blob.ErrBlobNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, blob.ErrAccessDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, blob.ErrUploadExpired), errors.Is(err, blob.ErrUploadIncomplete):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, "blob operation failed")
	}
}
