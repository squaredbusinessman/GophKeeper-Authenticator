package vaultkey

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func testKDFParams() KDFParams {
	return KDFParams{
		Algorithm:   KDFAlgorithm,
		TimeCost:    1,
		MemoryKiB:   8 * 1024,
		Parallelism: 1,
		KeyLength:   chacha20poly1305.KeySize,
	}
}

func TestGenerateReturnsVaultKeyWithExpectedLength(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(key) != KeyLength {
		t.Fatalf("key length = %d, want %d", len(key), KeyLength)
	}
}

func TestGenerateReturnsDifferentKeys(t *testing.T) {
	firstKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() first error = %v", err)
	}

	secondKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() second error = %v", err)
	}

	if bytes.Equal(firstKey, secondKey) {
		t.Fatalf("generated keys are equal, want different keys")
	}
}

func TestEncryptAndDecryptReturnsOriginalVaultKey(t *testing.T) {
	vaultKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	envelope, err := EncryptWithParams("master-password", vaultKey, testKDFParams())
	if err != nil {
		t.Fatalf("EncryptWithParams() error = %v", err)
	}

	decryptedVaultKey, err := Decrypt("master-password", envelope)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decryptedVaultKey, vaultKey) {
		t.Fatalf("decrypted vault key does not match original vault key")
	}
}

func TestEncryptDoesNotStorePlainVaultKey(t *testing.T) {
	vaultKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	envelope, err := EncryptWithParams("master-password", vaultKey, testKDFParams())
	if err != nil {
		t.Fatalf("EncryptWithParams() error = %v", err)
	}

	if bytes.Contains(envelope.EncryptedVaultKey, vaultKey) {
		t.Fatalf("encrypted vault key contains plaintext vault key")
	}
}

func TestDecryptReturnsErrorForWrongMasterPassword(t *testing.T) {
	vaultKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	envelope, err := EncryptWithParams("master-password", vaultKey, testKDFParams())
	if err != nil {
		t.Fatalf("EncryptWithParams() error = %v", err)
	}

	_, err = Decrypt("wrong-master-password", envelope)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestEncryptReturnsErrorForEmptyMasterPassword(t *testing.T) {
	vaultKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	_, err = EncryptWithParams("", vaultKey, testKDFParams())
	if err == nil {
		t.Fatalf("EncryptWithParams() error = nil, want error")
	}
}

func TestEncryptReturnsErrorForInvalidVaultKeyLength(t *testing.T) {
	_, err := EncryptWithParams("master-password", []byte("short-key"), testKDFParams())
	if err == nil {
		t.Fatalf("EncryptWithParams() error = nil, want error")
	}
}

func TestEncryptReturnsErrorForInvalidKDFParams(t *testing.T) {
	vaultKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	params := testKDFParams()
	params.MemoryKiB = 0

	_, err = EncryptWithParams("master-password", vaultKey, params)
	if err == nil {
		t.Fatalf("EncryptWithParams() error = nil, want error")
	}
}

func TestDecryptReturnsErrorForDamagedCiphertext(t *testing.T) {
	vaultKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	envelope, err := EncryptWithParams("master-password", vaultKey, testKDFParams())
	if err != nil {
		t.Fatalf("EncryptWithParams() error = %v", err)
	}

	envelope.EncryptedVaultKey[0] ^= 0xff

	_, err = Decrypt("master-password", envelope)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestDecryptReturnsErrorForEnvelopeWithoutSalt(t *testing.T) {
	vaultKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	envelope, err := EncryptWithParams("master-password", vaultKey, testKDFParams())
	if err != nil {
		t.Fatalf("EncryptWithParams() error = %v", err)
	}

	envelope.KDFParams.Salt = nil

	_, err = Decrypt("master-password", envelope)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestEnvelopeContainsEncryptionMetadata(t *testing.T) {
	vaultKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	envelope, err := EncryptWithParams("master-password", vaultKey, testKDFParams())
	if err != nil {
		t.Fatalf("EncryptWithParams() error = %v", err)
	}

	if envelope.EncryptionAlg != EncryptionAlgorithm {
		t.Fatalf("EncryptionAlg = %q, want %q", envelope.EncryptionAlg, EncryptionAlgorithm)
	}

	if len(envelope.Nonce) != chacha20poly1305.NonceSizeX {
		t.Fatalf("nonce length = %d, want %d", len(envelope.Nonce), chacha20poly1305.NonceSizeX)
	}

	if envelope.KDFParams.Algorithm != KDFAlgorithm {
		t.Fatalf("KDF algorithm = %q, want %q", envelope.KDFParams.Algorithm, KDFAlgorithm)
	}

	if len(envelope.KDFParams.Salt) == 0 {
		t.Fatalf("KDF salt is empty")
	}
}
