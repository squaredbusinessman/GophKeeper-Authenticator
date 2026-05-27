package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/crypto/payload"
)

const defaultBinaryPlaintextChunkSize = 3 * 1024 * 1024

// UploadBinaryInput содержит plaintext binary file для загрузки в BlobService
type UploadBinaryInput struct {
	FileName    string
	ContentType string
	Data        []byte
}

// DownloadBinaryInput содержит metadata binary payload для скачивания из BlobService
type DownloadBinaryInput struct {
	Payload BinaryPayload
}

// UploadBinary шифрует binary chunks и сохраняет их через BlobService
func (s *BlobService) UploadBinary(ctx context.Context, session Session, input UploadBinaryInput) (BinaryPayload, error) {
	if err := s.validateDependencies(); err != nil {
		return BinaryPayload{}, err
	}
	if err := validateSession(session); err != nil {
		return BinaryPayload{}, err
	}
	if input.FileName == "" {
		return BinaryPayload{}, fmt.Errorf("file name is required")
	}
	if len(input.Data) == 0 {
		return BinaryPayload{}, fmt.Errorf("binary data is required")
	}

	plaintextChecksum := sha256.Sum256(input.Data)
	chunks, encryptedSize, encryptedChecksum, err := encryptedBinaryChunks(session.VaultKey, input.Data)
	if err != nil {
		return BinaryPayload{}, err
	}

	upload, err := s.CreateUpload(ctx, session, CreateBlobUploadInput{
		ExpectedSize:   encryptedSize,
		ChunkSize:      maxBlobChunkSize(chunks),
		ExpectedChunks: int32(len(chunks)),
		ChecksumSHA256: encryptedChecksum,
	})
	if err != nil {
		return BinaryPayload{}, err
	}

	uploaded, err := s.Upload(ctx, session, UploadBlobInput{
		UploadID: upload.ID,
		Chunks:   chunks,
	})
	if err != nil {
		_ = s.AbortUpload(ctx, session, AbortBlobUploadInput{UploadID: upload.ID})
		return BinaryPayload{}, err
	}

	value := BinaryPayload{
		FileName:       input.FileName,
		ContentType:    input.ContentType,
		SizeBytes:      int64(len(input.Data)),
		ChecksumSHA256: hex.EncodeToString(plaintextChecksum[:]),
		BlobID:         uploaded.ID,
	}
	if _, _, err = EncodeBinaryPayload(value); err != nil {
		return BinaryPayload{}, err
	}

	return value, nil
}

// DownloadBinary скачивает encrypted chunks из BlobService и расшифровывает файл
func (s *BlobService) DownloadBinary(ctx context.Context, session Session, input DownloadBinaryInput) ([]byte, error) {
	if err := s.validateDependencies(); err != nil {
		return nil, err
	}
	if err := validateSession(session); err != nil {
		return nil, err
	}
	if _, _, err := EncodeBinaryPayload(input.Payload); err != nil {
		return nil, err
	}

	result, err := s.Download(ctx, session, DownloadBlobInput{BlobID: input.Payload.BlobID})
	if err != nil {
		return nil, err
	}

	sort.Slice(result.Chunks, func(i int, j int) bool {
		return result.Chunks[i].Index < result.Chunks[j].Index
	})

	var plaintext []byte
	for _, chunk := range result.Chunks {
		var encrypted payload.EncryptedPayload
		if err = json.Unmarshal(chunk.Data, &encrypted); err != nil {
			return nil, fmt.Errorf("decode encrypted binary chunk: %w", err)
		}

		data, err := payload.Decrypt(session.VaultKey, encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt binary chunk: %w", err)
		}

		plaintext = append(plaintext, data...)
	}

	if int64(len(plaintext)) != input.Payload.SizeBytes {
		return nil, fmt.Errorf("binary size mismatch")
	}

	checksum := sha256.Sum256(plaintext)
	if hex.EncodeToString(checksum[:]) != input.Payload.ChecksumSHA256 {
		return nil, fmt.Errorf("binary checksum mismatch")
	}

	return plaintext, nil
}

func encryptedBinaryChunks(vaultKey []byte, data []byte) ([]BlobChunk, int64, string, error) {
	hasher := sha256.New()
	chunks := make([]BlobChunk, 0, (len(data)+defaultBinaryPlaintextChunkSize-1)/defaultBinaryPlaintextChunkSize)
	var encryptedSize int64

	for index, offset := int32(0), 0; offset < len(data); index, offset = index+1, offset+defaultBinaryPlaintextChunkSize {
		end := offset + defaultBinaryPlaintextChunkSize
		if end > len(data) {
			end = len(data)
		}

		encrypted, err := payload.Encrypt(vaultKey, data[offset:end])
		if err != nil {
			return nil, 0, "", fmt.Errorf("encrypt binary chunk: %w", err)
		}

		chunkData, err := json.Marshal(encrypted)
		if err != nil {
			return nil, 0, "", fmt.Errorf("encode encrypted binary chunk: %w", err)
		}

		chunkChecksum := sha256.Sum256(chunkData)
		_, _ = hasher.Write(chunkData)
		encryptedSize += int64(len(chunkData))

		chunks = append(chunks, BlobChunk{
			Index:          index,
			Data:           chunkData,
			ChecksumSHA256: hex.EncodeToString(chunkChecksum[:]),
		})
	}

	return chunks, encryptedSize, hex.EncodeToString(hasher.Sum(nil)), nil
}

func maxBlobChunkSize(chunks []BlobChunk) int64 {
	var maxSize int64
	for _, chunk := range chunks {
		if int64(len(chunk.Data)) > maxSize {
			maxSize = int64(len(chunk.Data))
		}
	}

	return maxSize
}
