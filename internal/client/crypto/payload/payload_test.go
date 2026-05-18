package payload

import (
	"bytes"
	"testing"
)

func testVaultKey() []byte {
	return bytes.Repeat([]byte{1}, KeyLength)
}

func TestEncryptAndDecryptReturnsOriginalPayload(t *testing.T) {
	vaultKey := testVaultKey()
	plaintext := []byte("secret payload")

	encryptedPayload, err := Encrypt(vaultKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decryptedPayload, err := Decrypt(vaultKey, encryptedPayload)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decryptedPayload, plaintext) {
		t.Fatalf("decrypted payload does not match original payload")
	}
}

func TestEncryptDoesNotStorePlaintext(t *testing.T) {
	vaultKey := testVaultKey()
	plaintext := []byte("very-sensitive-secret")

	encryptedPayload, err := Encrypt(vaultKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if bytes.Contains(encryptedPayload.Ciphertext, plaintext) {
		t.Fatalf("ciphertext contains plaintext")
	}
}

func TestEncryptReturnsDifferentCiphertextsForSamePayload(t *testing.T) {
	vaultKey := testVaultKey()
	plaintext := []byte("same secret payload")

	firstEncryptedPayload, err := Encrypt(vaultKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() first error = %v", err)
	}

	secondEncryptedPayload, err := Encrypt(vaultKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() second error = %v", err)
	}

	if bytes.Equal(firstEncryptedPayload.Nonce, secondEncryptedPayload.Nonce) {
		t.Fatalf("nonces are equal, want different nonces")
	}

	if bytes.Equal(firstEncryptedPayload.Ciphertext, secondEncryptedPayload.Ciphertext) {
		t.Fatalf("ciphertexts are equal, want different ciphertexts")
	}
}

func TestDecryptReturnsErrorForWrongVaultKey(t *testing.T) {
	vaultKey := testVaultKey()
	wrongVaultKey := bytes.Repeat([]byte{2}, KeyLength)

	encryptedPayload, err := Encrypt(vaultKey, []byte("secret payload"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = Decrypt(wrongVaultKey, encryptedPayload)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestDecryptReturnsErrorForDamagedCiphertext(t *testing.T) {
	vaultKey := testVaultKey()

	encryptedPayload, err := Encrypt(vaultKey, []byte("secret payload"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encryptedPayload.Ciphertext[0] ^= 0xff

	_, err = Decrypt(vaultKey, encryptedPayload)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestDecryptReturnsErrorForDamagedNonce(t *testing.T) {
	vaultKey := testVaultKey()

	encryptedPayload, err := Encrypt(vaultKey, []byte("secret payload"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encryptedPayload.Nonce[0] ^= 0xff

	_, err = Decrypt(vaultKey, encryptedPayload)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestEncryptReturnsErrorForInvalidVaultKeyLength(t *testing.T) {
	_, err := Encrypt([]byte("short-key"), []byte("secret payload"))
	if err == nil {
		t.Fatalf("Encrypt() error = nil, want error")
	}
}

func TestDecryptReturnsErrorForInvalidVaultKeyLength(t *testing.T) {
	encryptedPayload, err := Encrypt(testVaultKey(), []byte("secret payload"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = Decrypt([]byte("short-key"), encryptedPayload)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestDecryptReturnsErrorForEmptyCiphertext(t *testing.T) {
	encryptedPayload := EncryptedPayload{
		Ciphertext: nil,
		Nonce:      bytes.Repeat([]byte{1}, NonceLength),
	}

	_, err := Decrypt(testVaultKey(), encryptedPayload)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestDecryptReturnsErrorForInvalidNonceLength(t *testing.T) {
	encryptedPayload := EncryptedPayload{
		Ciphertext: []byte("ciphertext"),
		Nonce:      []byte("short"),
	}

	_, err := Decrypt(testVaultKey(), encryptedPayload)
	if err == nil {
		t.Fatalf("Decrypt() error = nil, want error")
	}
}

func TestEncryptSupportsEmptyPayload(t *testing.T) {
	vaultKey := testVaultKey()

	encryptedPayload, err := Encrypt(vaultKey, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decryptedPayload, err := Decrypt(vaultKey, encryptedPayload)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if len(decryptedPayload) != 0 {
		t.Fatalf("decrypted payload length = %d, want 0", len(decryptedPayload))
	}
}
