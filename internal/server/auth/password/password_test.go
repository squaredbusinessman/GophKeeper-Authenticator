package password

import (
	"strings"
	"testing"
)

func testParams() Params {
	return Params{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestHashAndVerifyReturnsTrueForCorrectPassword(t *testing.T) {
	hash, err := HashWithParams("correct-password", testParams())
	if err != nil {
		t.Fatalf("HashWithParams() error = %v", err)
	}

	ok, err := Verify("correct-password", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !ok {
		t.Fatalf("Verify() = false, want true")
	}
}

func TestVerifyReturnsFalseForWrongPassword(t *testing.T) {
	hash, err := HashWithParams("correct-password", testParams())
	if err != nil {
		t.Fatalf("HashWithParams() error = %v", err)
	}

	ok, err := Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if ok {
		t.Fatalf("Verify() = true, want false")
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	firstHash, err := HashWithParams("same-password", testParams())
	if err != nil {
		t.Fatalf("HashWithParams() first error = %v", err)
	}

	secondHash, err := HashWithParams("same-password", testParams())
	if err != nil {
		t.Fatalf("HashWithParams() second error = %v", err)
	}

	if firstHash == secondHash {
		t.Fatalf("hashes are equal, want different hashes because salt must be random")
	}
}

func TestHashReturnsPHCStyleString(t *testing.T) {
	hash, err := HashWithParams("password", testParams())
	if err != nil {
		t.Fatalf("HashWithParams() error = %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("hash = %q, want argon2id PHC style prefix", hash)
	}
}

func TestVerifyReturnsErrorForInvalidHash(t *testing.T) {
	_, err := Verify("password", "invalid-hash")
	if err == nil {
		t.Fatalf("Verify() error = nil, want error")
	}
}

func TestHashReturnsErrorForEmptyPassword(t *testing.T) {
	_, err := HashWithParams("", testParams())
	if err == nil {
		t.Fatalf("HashWithParams() error = nil, want error")
	}
}

func TestVerifyReturnsErrorForEmptyPassword(t *testing.T) {
	hash, err := HashWithParams("password", testParams())
	if err != nil {
		t.Fatalf("HashWithParams() error = %v", err)
	}

	_, err = Verify("", hash)
	if err == nil {
		t.Fatalf("Verify() error = nil, want error")
	}
}

func TestHashWithParamsReturnsErrorForInvalidParams(t *testing.T) {
	params := testParams()
	params.Memory = 0

	_, err := HashWithParams("password", params)
	if err == nil {
		t.Fatalf("HashWithParams() error = nil, want error")
	}
}

func TestDecodeReturnsParamsSaltAndHash(t *testing.T) {
	hash, err := HashWithParams("password", testParams())
	if err != nil {
		t.Fatalf("HashWithParams() error = %v", err)
	}

	params, salt, rawHash, err := Decode(hash)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if params.Memory != testParams().Memory {
		t.Fatalf("Memory = %d, want %d", params.Memory, testParams().Memory)
	}

	if len(salt) != int(testParams().SaltLength) {
		t.Fatalf("salt length = %d, want %d", len(salt), testParams().SaltLength)
	}

	if len(rawHash) != int(testParams().KeyLength) {
		t.Fatalf("hash length = %d, want %d", len(rawHash), testParams().KeyLength)
	}
}
