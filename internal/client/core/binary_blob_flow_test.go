package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestBlobServiceUploadBinaryStoresEncryptedChunksAndReturnsMetadata(t *testing.T) {
	session := testSession()
	stream := &fakeBlobUploadStream{
		response: gophkeeperv1.UploadBlobResponse_builder{
			BlobId:         "blob-id",
			StorageBucket:  "bucket",
			ObjectPrefix:   "prefix",
			ChunkSize:      1024,
			ChunkCount:     1,
			SizeBytes:      128,
			ChecksumSha256: "encrypted-checksum",
		}.Build(),
	}
	blobClient := &fakeBlobClient{
		createBlobUploadFunc: func(ctx context.Context, req *gophkeeperv1.CreateBlobUploadRequest, _ ...grpc.CallOption) (*gophkeeperv1.CreateBlobUploadResponse, error) {
			assertOutgoingBearerToken(ctx, t, session.AccessToken)
			if req.GetExpectedChunks() != 1 {
				t.Fatalf("expected chunks = %d, want 1", req.GetExpectedChunks())
			}
			if req.GetExpectedSize() <= int64(len("binary payload")) {
				t.Fatalf("expected encrypted size = %d, want larger than plaintext", req.GetExpectedSize())
			}
			if strings.TrimSpace(req.GetChecksumSha256()) == "" {
				t.Fatalf("encrypted checksum is empty")
			}

			return gophkeeperv1.CreateBlobUploadResponse_builder{
				UploadId:  "upload-id",
				ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
				ChunkSize: req.GetChunkSize(),
			}.Build(), nil
		},
		uploadBlobFunc: func(ctx context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[gophkeeperv1.UploadBlobChunkRequest, gophkeeperv1.UploadBlobResponse], error) {
			assertOutgoingBearerToken(ctx, t, session.AccessToken)
			return stream, nil
		},
	}
	service := NewBlobService(blobClient)

	metadata, err := service.UploadBinary(context.Background(), session, UploadBinaryInput{
		FileName:    "secret.bin",
		ContentType: "application/octet-stream",
		Data:        []byte("binary payload"),
	})
	if err != nil {
		t.Fatalf("UploadBinary() error = %v", err)
	}

	checksum := sha256.Sum256([]byte("binary payload"))
	if metadata.BlobID != "blob-id" {
		t.Fatalf("blob id = %q, want blob-id", metadata.BlobID)
	}
	if metadata.ChecksumSHA256 != hex.EncodeToString(checksum[:]) {
		t.Fatalf("plaintext checksum = %q, want %q", metadata.ChecksumSHA256, hex.EncodeToString(checksum[:]))
	}
	if metadata.SizeBytes != int64(len("binary payload")) {
		t.Fatalf("size bytes = %d, want plaintext size", metadata.SizeBytes)
	}
	if len(stream.sentChunks) != 1 {
		t.Fatalf("sent chunks = %d, want 1", len(stream.sentChunks))
	}
	if bytes.Contains(stream.sentChunks[0].GetData(), []byte("binary payload")) {
		t.Fatalf("uploaded chunk contains plaintext")
	}
}

func TestBlobServiceDownloadBinaryDecryptsSortedChunks(t *testing.T) {
	session := testSession()
	plaintext := []byte(strings.Repeat("a", defaultBinaryPlaintextChunkSize+32))
	chunks, _, _, err := encryptedBinaryChunks(session.VaultKey, plaintext)
	if err != nil {
		t.Fatalf("encryptedBinaryChunks() error = %v", err)
	}
	checksum := sha256.Sum256(plaintext)
	stream := &fakeBlobDownloadStream{
		chunks: []*gophkeeperv1.DownloadBlobChunk{
			downloadBlobChunk("blob-id", chunks[1]),
			downloadBlobChunk("blob-id", chunks[0]),
		},
	}
	blobClient := &fakeBlobClient{
		downloadBlobFunc: func(ctx context.Context, req *gophkeeperv1.DownloadBlobRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[gophkeeperv1.DownloadBlobChunk], error) {
			assertOutgoingBearerToken(ctx, t, session.AccessToken)
			if req.GetBlobId() != "blob-id" {
				t.Fatalf("blob id = %q, want blob-id", req.GetBlobId())
			}
			return stream, nil
		},
	}
	service := NewBlobService(blobClient)

	result, err := service.DownloadBinary(context.Background(), session, DownloadBinaryInput{
		Payload: BinaryPayload{
			FileName:       "secret.bin",
			SizeBytes:      int64(len(plaintext)),
			ChecksumSHA256: hex.EncodeToString(checksum[:]),
			BlobID:         "blob-id",
		},
	})
	if err != nil {
		t.Fatalf("DownloadBinary() error = %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Fatalf("downloaded binary does not match plaintext")
	}
}

func TestBlobServiceUploadBinaryAbortsUploadWhenStreamFails(t *testing.T) {
	session := testSession()
	stream := &fakeBlobUploadStream{
		closeErr: errors.New("stream failed"),
	}
	blobClient := &fakeBlobClient{
		createBlobUploadFunc: func(context.Context, *gophkeeperv1.CreateBlobUploadRequest, ...grpc.CallOption) (*gophkeeperv1.CreateBlobUploadResponse, error) {
			return gophkeeperv1.CreateBlobUploadResponse_builder{
				UploadId:  "upload-id",
				ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
				ChunkSize: 1024,
			}.Build(), nil
		},
		uploadBlobFunc: func(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[gophkeeperv1.UploadBlobChunkRequest, gophkeeperv1.UploadBlobResponse], error) {
			return stream, nil
		},
		abortBlobUploadFunc: func(_ context.Context, req *gophkeeperv1.AbortBlobUploadRequest, _ ...grpc.CallOption) (*gophkeeperv1.AbortBlobUploadResponse, error) {
			if req.GetUploadId() != "upload-id" {
				t.Fatalf("abort upload id = %q, want upload-id", req.GetUploadId())
			}
			return gophkeeperv1.AbortBlobUploadResponse_builder{}.Build(), nil
		},
	}
	service := NewBlobService(blobClient)

	_, err := service.UploadBinary(context.Background(), session, UploadBinaryInput{
		FileName: "secret.bin",
		Data:     []byte("binary payload"),
	})
	if err == nil {
		t.Fatalf("UploadBinary() error = nil, want stream error")
	}
	if len(blobClient.abortBlobUploadCalls) != 1 {
		t.Fatalf("AbortBlobUpload() calls = %d, want 1", len(blobClient.abortBlobUploadCalls))
	}
}

func TestBlobServiceDownloadBinaryRejectsChecksumMismatch(t *testing.T) {
	session := testSession()
	chunks, _, _, err := encryptedBinaryChunks(session.VaultKey, []byte("binary payload"))
	if err != nil {
		t.Fatalf("encryptedBinaryChunks() error = %v", err)
	}
	stream := &fakeBlobDownloadStream{
		chunks: []*gophkeeperv1.DownloadBlobChunk{
			downloadBlobChunk("blob-id", chunks[0]),
		},
	}
	blobClient := &fakeBlobClient{
		downloadBlobFunc: func(context.Context, *gophkeeperv1.DownloadBlobRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[gophkeeperv1.DownloadBlobChunk], error) {
			return stream, nil
		},
	}
	service := NewBlobService(blobClient)

	_, err = service.DownloadBinary(context.Background(), session, DownloadBinaryInput{
		Payload: BinaryPayload{
			FileName:       "secret.bin",
			SizeBytes:      int64(len("binary payload")),
			ChecksumSHA256: "wrong-checksum",
			BlobID:         "blob-id",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "binary checksum mismatch") {
		t.Fatalf("DownloadBinary() error = %v, want checksum mismatch", err)
	}
}

func downloadBlobChunk(blobID string, chunk BlobChunk) *gophkeeperv1.DownloadBlobChunk {
	return gophkeeperv1.DownloadBlobChunk_builder{
		BlobId:         blobID,
		ChunkIndex:     chunk.Index,
		Data:           chunk.Data,
		ChecksumSha256: chunk.ChecksumSHA256,
	}.Build()
}
