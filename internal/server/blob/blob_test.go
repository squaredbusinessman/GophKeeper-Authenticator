package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"testing"
	"time"
)

type fakeBlobRepository struct {
	uploads map[string]Upload
	parts   map[string][]UploadPart
	blobs   map[string]Blob
}

func newFakeBlobRepository() *fakeBlobRepository {
	return &fakeBlobRepository{
		uploads: map[string]Upload{},
		parts:   map[string][]UploadPart{},
		blobs:   map[string]Blob{},
	}
}

func (r *fakeBlobRepository) CreateUpload(_ context.Context, params CreateUploadParams) (Upload, error) {
	upload := Upload{
		ID:             params.UploadID,
		UserID:         params.UserID,
		Status:         params.Status,
		ChunkSize:      params.ChunkSize,
		ExpectedSize:   params.ExpectedSize,
		ExpectedChunks: params.ExpectedChunks,
		ChecksumSHA256: params.ChecksumSHA256,
		ExpiresAt:      params.ExpiresAt,
	}
	r.uploads[upload.ID] = upload
	return upload, nil
}

func (r *fakeBlobRepository) FindUploadByID(_ context.Context, uploadID string) (Upload, error) {
	upload, ok := r.uploads[uploadID]
	if !ok {
		return Upload{}, ErrUploadNotFound
	}

	return upload, nil
}

func (r *fakeBlobRepository) AddUploadPart(_ context.Context, params AddUploadPartParams) error {
	upload, ok := r.uploads[params.UploadID]
	if !ok {
		return ErrUploadNotFound
	}

	part := UploadPart{
		UploadID:       params.UploadID,
		ChunkIndex:     params.ChunkIndex,
		ObjectKey:      params.ObjectKey,
		SizeBytes:      params.SizeBytes,
		ChecksumSHA256: params.ChecksumSHA256,
	}

	parts := r.parts[params.UploadID]
	replaced := false
	for index := range parts {
		if parts[index].ChunkIndex == params.ChunkIndex {
			parts[index] = part
			replaced = true
			break
		}
	}
	if !replaced {
		parts = append(parts, part)
	}

	sort.Slice(parts, func(i int, j int) bool {
		return parts[i].ChunkIndex < parts[j].ChunkIndex
	})

	upload.Status = UploadStatusUploading
	upload.ReceivedChunks = int32(len(parts))
	r.uploads[params.UploadID] = upload
	r.parts[params.UploadID] = parts

	return nil
}

func (r *fakeBlobRepository) ListUploadParts(_ context.Context, uploadID string) ([]UploadPart, error) {
	parts := append([]UploadPart(nil), r.parts[uploadID]...)
	sort.Slice(parts, func(i int, j int) bool {
		return parts[i].ChunkIndex < parts[j].ChunkIndex
	})
	return parts, nil
}

func (r *fakeBlobRepository) CommitUpload(_ context.Context, params CommitUploadParams) (Blob, error) {
	upload, ok := r.uploads[params.UploadID]
	if !ok {
		return Blob{}, ErrUploadNotFound
	}
	if upload.UserID != params.UserID {
		return Blob{}, ErrAccessDenied
	}

	parts := r.parts[params.UploadID]
	var size int64
	for _, part := range parts {
		size += part.SizeBytes
	}
	if int32(len(parts)) != upload.ExpectedChunks || size != upload.ExpectedSize {
		return Blob{}, ErrUploadIncomplete
	}

	blobItem := Blob{
		ID:             params.BlobID,
		UserID:         params.UserID,
		UploadID:       params.UploadID,
		Status:         BlobStatusReady,
		StorageBucket:  params.StorageBucket,
		ObjectPrefix:   params.ObjectPrefix,
		ChunkSize:      upload.ChunkSize,
		ChunkCount:     int32(len(parts)),
		SizeBytes:      size,
		ChecksumSHA256: params.ChecksumSHA256,
	}

	upload.Status = UploadStatusCommitted
	upload.ReceivedChunks = int32(len(parts))
	r.uploads[params.UploadID] = upload
	r.blobs[blobItem.ID] = blobItem

	return blobItem, nil
}

func (r *fakeBlobRepository) AbortUpload(_ context.Context, params AbortUploadParams) error {
	upload, ok := r.uploads[params.UploadID]
	if !ok {
		return ErrUploadNotFound
	}
	if upload.UserID != params.UserID {
		return ErrAccessDenied
	}

	upload.Status = UploadStatusAborted
	r.uploads[params.UploadID] = upload
	return nil
}

func (r *fakeBlobRepository) FindBlobByID(_ context.Context, blobID string) (Blob, error) {
	blobItem, ok := r.blobs[blobID]
	if !ok {
		return Blob{}, ErrBlobNotFound
	}

	return blobItem, nil
}

type fakeObjectStore struct {
	objects map[string][]byte
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{
		objects: map[string][]byte{},
	}
}

func (s *fakeObjectStore) EnsureBucket(context.Context) error {
	return nil
}

func (s *fakeObjectStore) PutObject(_ context.Context, input PutObjectInput) error {
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return err
	}

	s.objects[input.Key] = data
	return nil
}

func (s *fakeObjectStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	data, ok := s.objects[key]
	if !ok {
		return nil, errors.New("object not found")
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *fakeObjectStore) StatObject(_ context.Context, key string) (ObjectInfo, error) {
	data, ok := s.objects[key]
	if !ok {
		return ObjectInfo{}, errors.New("object not found")
	}

	return ObjectInfo{
		Key:  key,
		Size: int64(len(data)),
	}, nil
}

func (s *fakeObjectStore) RemoveObject(_ context.Context, key string) error {
	delete(s.objects, key)
	return nil
}

type sequenceIDGenerator struct {
	ids []string
}

func (g *sequenceIDGenerator) NewID() (string, error) {
	if len(g.ids) == 0 {
		return "", errors.New("id sequence is empty")
	}

	id := g.ids[0]
	g.ids = g.ids[1:]
	return id, nil
}

func TestServiceCreateUploadUsesDefaults(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	repository := newFakeBlobRepository()
	service := NewService(repository, newFakeObjectStore(), &sequenceIDGenerator{ids: []string{"upload-id"}}, Config{
		Bucket:    "bucket",
		ChunkSize: 4,
		MaxSize:   10,
		UploadTTL: time.Hour,
		Now: func() time.Time {
			return now
		},
	})

	upload, err := service.CreateUpload(context.Background(), CreateUploadInput{
		UserID:         "user-id",
		ExpectedSize:   8,
		ExpectedChunks: 2,
		ChecksumSHA256: "blob-checksum",
	})
	if err != nil {
		t.Fatalf("CreateUpload() error = %v", err)
	}

	if upload.ID != "upload-id" {
		t.Fatalf("upload id = %q, want upload-id", upload.ID)
	}
	if upload.ChunkSize != 4 {
		t.Fatalf("chunk size = %d, want 4", upload.ChunkSize)
	}
	if upload.ChecksumSHA256 != "blob-checksum" {
		t.Fatalf("checksum = %q, want blob-checksum", upload.ChecksumSHA256)
	}
	if !upload.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("expires at = %s, want %s", upload.ExpiresAt, now.Add(time.Hour))
	}
}

func TestServiceUploadCommitAndDownloadBlob(t *testing.T) {
	repository := newFakeBlobRepository()
	objectStore := newFakeObjectStore()
	service := NewService(repository, objectStore, &sequenceIDGenerator{ids: []string{"upload-id", "blob-id"}}, Config{
		Bucket:    "bucket",
		ChunkSize: 4,
		MaxSize:   8,
		UploadTTL: time.Hour,
		Now: func() time.Time {
			return time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
		},
	})

	upload, err := service.CreateUpload(context.Background(), CreateUploadInput{
		UserID:         "user-id",
		ExpectedSize:   7,
		ExpectedChunks: 2,
		ChecksumSHA256: "blob-checksum",
	})
	if err != nil {
		t.Fatalf("CreateUpload() error = %v", err)
	}

	firstChunk := []byte{0, 1, 2, 3}
	secondChunk := []byte{4, 5, 0}
	for index, data := range [][]byte{firstChunk, secondChunk} {
		if err = service.UploadChunk(context.Background(), UploadChunkInput{
			UserID:         "user-id",
			UploadID:       upload.ID,
			ChunkIndex:     int32(index),
			Data:           data,
			ChecksumSHA256: "chunk-checksum",
		}); err != nil {
			t.Fatalf("UploadChunk() error = %v", err)
		}
	}

	firstKey := uploadChunkObjectKey("user-id", upload.ID, 0)
	if !bytes.Equal(objectStore.objects[firstKey], firstChunk) {
		t.Fatalf("stored first chunk = %v, want %v", objectStore.objects[firstKey], firstChunk)
	}

	blobItem, err := service.CommitUpload(context.Background(), CommitUploadInput{
		UserID:   "user-id",
		UploadID: upload.ID,
	})
	if err != nil {
		t.Fatalf("CommitUpload() error = %v", err)
	}
	if blobItem.ID != "blob-id" {
		t.Fatalf("blob id = %q, want blob-id", blobItem.ID)
	}
	if blobItem.SizeBytes != 7 {
		t.Fatalf("blob size = %d, want 7", blobItem.SizeBytes)
	}
	if blobItem.ChecksumSHA256 != "blob-checksum" {
		t.Fatalf("blob checksum = %q, want blob-checksum", blobItem.ChecksumSHA256)
	}

	result, err := service.DownloadBlob(context.Background(), DownloadBlobInput{
		UserID: "user-id",
		BlobID: blobItem.ID,
	})
	if err != nil {
		t.Fatalf("DownloadBlob() error = %v", err)
	}
	if len(result.Parts) != 2 {
		t.Fatalf("download parts = %d, want 2", len(result.Parts))
	}

	reader, err := service.OpenObject(context.Background(), result.Parts[1].ObjectKey)
	if err != nil {
		t.Fatalf("OpenObject() error = %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if err = reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !bytes.Equal(data, secondChunk) {
		t.Fatalf("opened second chunk = %v, want %v", data, secondChunk)
	}
}

func TestServiceAbortUploadRemovesStoredChunks(t *testing.T) {
	repository := newFakeBlobRepository()
	objectStore := newFakeObjectStore()
	service := NewService(repository, objectStore, &sequenceIDGenerator{ids: []string{"upload-id"}}, Config{
		Bucket:    "bucket",
		ChunkSize: 4,
		MaxSize:   8,
		UploadTTL: time.Hour,
		Now:       time.Now,
	})

	upload, err := service.CreateUpload(context.Background(), CreateUploadInput{
		UserID:         "user-id",
		ExpectedSize:   4,
		ExpectedChunks: 1,
		ChecksumSHA256: "blob-checksum",
	})
	if err != nil {
		t.Fatalf("CreateUpload() error = %v", err)
	}

	if err = service.UploadChunk(context.Background(), UploadChunkInput{
		UserID:         "user-id",
		UploadID:       upload.ID,
		ChunkIndex:     0,
		Data:           []byte("data"),
		ChecksumSHA256: "chunk-checksum",
	}); err != nil {
		t.Fatalf("UploadChunk() error = %v", err)
	}

	if err = service.AbortUpload(context.Background(), AbortUploadInput{
		UserID:   "user-id",
		UploadID: upload.ID,
	}); err != nil {
		t.Fatalf("AbortUpload() error = %v", err)
	}

	if len(objectStore.objects) != 0 {
		t.Fatalf("objects count = %d, want 0", len(objectStore.objects))
	}
	if repository.uploads[upload.ID].Status != UploadStatusAborted {
		t.Fatalf("upload status = %q, want aborted", repository.uploads[upload.ID].Status)
	}
}

func TestServiceRejectsAccessToOtherUserBlob(t *testing.T) {
	repository := newFakeBlobRepository()
	objectStore := newFakeObjectStore()
	service := NewService(repository, objectStore, &sequenceIDGenerator{ids: []string{"upload-id", "blob-id"}}, Config{
		Bucket:    "bucket",
		ChunkSize: 4,
		MaxSize:   8,
		UploadTTL: time.Hour,
		Now:       time.Now,
	})

	upload, err := service.CreateUpload(context.Background(), CreateUploadInput{
		UserID:         "owner-id",
		ExpectedSize:   4,
		ExpectedChunks: 1,
		ChecksumSHA256: "blob-checksum",
	})
	if err != nil {
		t.Fatalf("CreateUpload() error = %v", err)
	}

	if err = service.UploadChunk(context.Background(), UploadChunkInput{
		UserID:         "owner-id",
		UploadID:       upload.ID,
		ChunkIndex:     0,
		Data:           []byte("data"),
		ChecksumSHA256: "chunk-checksum",
	}); err != nil {
		t.Fatalf("UploadChunk() error = %v", err)
	}

	blobItem, err := service.CommitUpload(context.Background(), CommitUploadInput{
		UserID:   "owner-id",
		UploadID: upload.ID,
	})
	if err != nil {
		t.Fatalf("CommitUpload() error = %v", err)
	}

	_, err = service.DownloadBlob(context.Background(), DownloadBlobInput{
		UserID: "other-id",
		BlobID: blobItem.ID,
	})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("DownloadBlob() error = %v, want ErrAccessDenied", err)
	}
}

func TestServiceRejectsExpiredUpload(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	service := NewService(newFakeBlobRepository(), newFakeObjectStore(), &sequenceIDGenerator{ids: []string{"upload-id"}}, Config{
		Bucket:    "bucket",
		ChunkSize: 4,
		MaxSize:   8,
		UploadTTL: time.Minute,
		Now: func() time.Time {
			return now
		},
	})

	upload, err := service.CreateUpload(context.Background(), CreateUploadInput{
		UserID:         "user-id",
		ExpectedSize:   4,
		ExpectedChunks: 1,
		ChecksumSHA256: "blob-checksum",
	})
	if err != nil {
		t.Fatalf("CreateUpload() error = %v", err)
	}

	service.now = func() time.Time {
		return now.Add(2 * time.Minute)
	}

	err = service.UploadChunk(context.Background(), UploadChunkInput{
		UserID:         "user-id",
		UploadID:       upload.ID,
		ChunkIndex:     0,
		Data:           []byte("data"),
		ChecksumSHA256: "chunk-checksum",
	})
	if !errors.Is(err, ErrUploadExpired) {
		t.Fatalf("UploadChunk() error = %v, want ErrUploadExpired", err)
	}
}
