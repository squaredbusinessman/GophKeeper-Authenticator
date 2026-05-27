package core

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeBlobClient struct {
	createBlobUploadFunc func(context.Context, *gophkeeperv1.CreateBlobUploadRequest, ...grpc.CallOption) (*gophkeeperv1.CreateBlobUploadResponse, error)
	uploadBlobFunc       func(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[gophkeeperv1.UploadBlobChunkRequest, gophkeeperv1.UploadBlobResponse], error)
	downloadBlobFunc     func(context.Context, *gophkeeperv1.DownloadBlobRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[gophkeeperv1.DownloadBlobChunk], error)
	abortBlobUploadFunc  func(context.Context, *gophkeeperv1.AbortBlobUploadRequest, ...grpc.CallOption) (*gophkeeperv1.AbortBlobUploadResponse, error)

	createBlobUploadCalls []vaultClientCall[*gophkeeperv1.CreateBlobUploadRequest]
	downloadBlobCalls     []vaultClientCall[*gophkeeperv1.DownloadBlobRequest]
	abortBlobUploadCalls  []vaultClientCall[*gophkeeperv1.AbortBlobUploadRequest]
}

func (c *fakeBlobClient) CreateBlobUpload(ctx context.Context, req *gophkeeperv1.CreateBlobUploadRequest, opts ...grpc.CallOption) (*gophkeeperv1.CreateBlobUploadResponse, error) {
	c.createBlobUploadCalls = append(c.createBlobUploadCalls, vaultClientCall[*gophkeeperv1.CreateBlobUploadRequest]{
		ctx: ctx,
		req: req,
	})
	if c.createBlobUploadFunc != nil {
		return c.createBlobUploadFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected create blob upload call")
}

func (c *fakeBlobClient) UploadBlob(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[gophkeeperv1.UploadBlobChunkRequest, gophkeeperv1.UploadBlobResponse], error) {
	if c.uploadBlobFunc != nil {
		return c.uploadBlobFunc(ctx, opts...)
	}

	return nil, errors.New("unexpected upload blob call")
}

func (c *fakeBlobClient) DownloadBlob(ctx context.Context, req *gophkeeperv1.DownloadBlobRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[gophkeeperv1.DownloadBlobChunk], error) {
	c.downloadBlobCalls = append(c.downloadBlobCalls, vaultClientCall[*gophkeeperv1.DownloadBlobRequest]{
		ctx: ctx,
		req: req,
	})
	if c.downloadBlobFunc != nil {
		return c.downloadBlobFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected download blob call")
}

func (c *fakeBlobClient) AbortBlobUpload(ctx context.Context, req *gophkeeperv1.AbortBlobUploadRequest, opts ...grpc.CallOption) (*gophkeeperv1.AbortBlobUploadResponse, error) {
	c.abortBlobUploadCalls = append(c.abortBlobUploadCalls, vaultClientCall[*gophkeeperv1.AbortBlobUploadRequest]{
		ctx: ctx,
		req: req,
	})
	if c.abortBlobUploadFunc != nil {
		return c.abortBlobUploadFunc(ctx, req, opts...)
	}

	return nil, errors.New("unexpected abort blob upload call")
}

type fakeBlobUploadStream struct {
	grpc.ClientStream

	sentChunks []*gophkeeperv1.UploadBlobChunkRequest
	response   *gophkeeperv1.UploadBlobResponse
	sendErr    error
	closeErr   error
}

func (s *fakeBlobUploadStream) Send(req *gophkeeperv1.UploadBlobChunkRequest) error {
	if s.sendErr != nil {
		return s.sendErr
	}

	s.sentChunks = append(s.sentChunks, req)
	return nil
}

func (s *fakeBlobUploadStream) CloseAndRecv() (*gophkeeperv1.UploadBlobResponse, error) {
	if s.closeErr != nil {
		return nil, s.closeErr
	}

	return s.response, nil
}

type fakeBlobDownloadStream struct {
	grpc.ClientStream

	chunks []*gophkeeperv1.DownloadBlobChunk
	index  int
}

func (s *fakeBlobDownloadStream) Recv() (*gophkeeperv1.DownloadBlobChunk, error) {
	if s.index >= len(s.chunks) {
		return nil, io.EOF
	}

	chunk := s.chunks[s.index]
	s.index++
	return chunk, nil
}

func TestBlobServiceCreateUploadSendsAccessToken(t *testing.T) {
	session := testSession()
	expiresAt := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	blobClient := &fakeBlobClient{
		createBlobUploadFunc: func(_ context.Context, req *gophkeeperv1.CreateBlobUploadRequest, _ ...grpc.CallOption) (*gophkeeperv1.CreateBlobUploadResponse, error) {
			if req.GetExpectedSize() != 12 {
				t.Fatalf("expected size = %d, want 12", req.GetExpectedSize())
			}
			if req.GetExpectedChunks() != 2 {
				t.Fatalf("expected chunks = %d, want 2", req.GetExpectedChunks())
			}
			if req.GetChecksumSha256() != "blob-checksum" {
				t.Fatalf("checksum = %q, want blob-checksum", req.GetChecksumSha256())
			}

			return &gophkeeperv1.CreateBlobUploadResponse{
				UploadId:  "upload-id",
				ExpiresAt: timestamppb.New(expiresAt),
				ChunkSize: 6,
			}, nil
		},
	}
	service := NewBlobService(blobClient)

	upload, err := service.CreateUpload(context.Background(), session, CreateBlobUploadInput{
		ExpectedSize:   12,
		ExpectedChunks: 2,
		ChecksumSHA256: "blob-checksum",
	})
	if err != nil {
		t.Fatalf("CreateUpload() error = %v", err)
	}

	if len(blobClient.createBlobUploadCalls) != 1 {
		t.Fatalf("CreateBlobUpload() calls = %d, want 1", len(blobClient.createBlobUploadCalls))
	}
	assertOutgoingBearerToken(blobClient.createBlobUploadCalls[0].ctx, t, session.AccessToken)

	if upload.ID != "upload-id" {
		t.Fatalf("upload id = %q, want upload-id", upload.ID)
	}
	if !upload.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expires at = %s, want %s", upload.ExpiresAt, expiresAt)
	}
	if upload.ChunkSize != 6 {
		t.Fatalf("chunk size = %d, want 6", upload.ChunkSize)
	}
}

func TestBlobServiceUploadSendsChunks(t *testing.T) {
	session := testSession()
	stream := &fakeBlobUploadStream{
		response: &gophkeeperv1.UploadBlobResponse{
			BlobId:         "blob-id",
			StorageBucket:  "bucket",
			ObjectPrefix:   "prefix",
			ChunkSize:      6,
			ChunkCount:     2,
			SizeBytes:      12,
			ChecksumSha256: "blob-checksum",
		},
	}
	blobClient := &fakeBlobClient{
		uploadBlobFunc: func(ctx context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[gophkeeperv1.UploadBlobChunkRequest, gophkeeperv1.UploadBlobResponse], error) {
			assertOutgoingBearerToken(ctx, t, session.AccessToken)
			return stream, nil
		},
	}
	service := NewBlobService(blobClient)

	uploaded, err := service.Upload(context.Background(), session, UploadBlobInput{
		UploadID: "upload-id",
		Chunks: []BlobChunk{
			{Index: 0, Data: []byte("first"), ChecksumSHA256: "chunk-0"},
			{Index: 1, Data: []byte("second"), ChecksumSHA256: "chunk-1"},
		},
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}

	if len(stream.sentChunks) != 2 {
		t.Fatalf("sent chunks = %d, want 2", len(stream.sentChunks))
	}
	if stream.sentChunks[1].GetUploadId() != "upload-id" {
		t.Fatalf("upload id = %q, want upload-id", stream.sentChunks[1].GetUploadId())
	}
	if string(stream.sentChunks[1].GetData()) != "second" {
		t.Fatalf("second chunk data = %q, want second", string(stream.sentChunks[1].GetData()))
	}
	if uploaded.ID != "blob-id" {
		t.Fatalf("uploaded blob id = %q, want blob-id", uploaded.ID)
	}
	if uploaded.SizeBytes != 12 {
		t.Fatalf("uploaded size = %d, want 12", uploaded.SizeBytes)
	}
}

func TestBlobServiceDownloadReceivesChunks(t *testing.T) {
	session := testSession()
	stream := &fakeBlobDownloadStream{
		chunks: []*gophkeeperv1.DownloadBlobChunk{
			{BlobId: "blob-id", ChunkIndex: 0, Data: []byte("first"), ChecksumSha256: "chunk-0"},
			{BlobId: "blob-id", ChunkIndex: 1, Data: []byte("second"), ChecksumSha256: "chunk-1"},
		},
	}
	blobClient := &fakeBlobClient{
		downloadBlobFunc: func(_ context.Context, req *gophkeeperv1.DownloadBlobRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[gophkeeperv1.DownloadBlobChunk], error) {
			if req.GetBlobId() != "blob-id" {
				t.Fatalf("blob id = %q, want blob-id", req.GetBlobId())
			}

			return stream, nil
		},
	}
	service := NewBlobService(blobClient)

	result, err := service.Download(context.Background(), session, DownloadBlobInput{
		BlobID: "blob-id",
	})
	if err != nil {
		t.Fatalf("Download() error = %v", err)
	}

	if len(blobClient.downloadBlobCalls) != 1 {
		t.Fatalf("DownloadBlob() calls = %d, want 1", len(blobClient.downloadBlobCalls))
	}
	assertOutgoingBearerToken(blobClient.downloadBlobCalls[0].ctx, t, session.AccessToken)

	if len(result.Chunks) != 2 {
		t.Fatalf("download chunks = %d, want 2", len(result.Chunks))
	}
	if string(result.Chunks[0].Data) != "first" {
		t.Fatalf("first chunk = %q, want first", string(result.Chunks[0].Data))
	}
}

func TestBlobServiceAbortUploadSendsAccessToken(t *testing.T) {
	session := testSession()
	blobClient := &fakeBlobClient{
		abortBlobUploadFunc: func(_ context.Context, req *gophkeeperv1.AbortBlobUploadRequest, _ ...grpc.CallOption) (*gophkeeperv1.AbortBlobUploadResponse, error) {
			if req.GetUploadId() != "upload-id" {
				t.Fatalf("upload id = %q, want upload-id", req.GetUploadId())
			}

			return &gophkeeperv1.AbortBlobUploadResponse{}, nil
		},
	}
	service := NewBlobService(blobClient)

	err := service.AbortUpload(context.Background(), session, AbortBlobUploadInput{
		UploadID: "upload-id",
	})
	if err != nil {
		t.Fatalf("AbortUpload() error = %v", err)
	}

	if len(blobClient.abortBlobUploadCalls) != 1 {
		t.Fatalf("AbortBlobUpload() calls = %d, want 1", len(blobClient.abortBlobUploadCalls))
	}
	assertOutgoingBearerToken(blobClient.abortBlobUploadCalls[0].ctx, t, session.AccessToken)
}
