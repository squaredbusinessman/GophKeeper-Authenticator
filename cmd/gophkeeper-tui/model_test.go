package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	clientapp "github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/app"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
)

type fakeAuthService struct {
	registerCalls []core.RegisterInput
	loginCalls    []core.LoginInput
	session       core.Session
	err           error
}

func (s *fakeAuthService) Register(_ context.Context, input core.RegisterInput) (core.Session, error) {
	s.registerCalls = append(s.registerCalls, input)
	if s.err != nil {
		return core.Session{}, s.err
	}
	return s.session, nil
}

func (s *fakeAuthService) Login(_ context.Context, input core.LoginInput) (core.Session, error) {
	s.loginCalls = append(s.loginCalls, input)
	if s.err != nil {
		return core.Session{}, s.err
	}
	return s.session, nil
}

type fakeVaultService struct {
	createCalls []core.CreateSecretInput
	updateCalls []core.UpdateSecretInput
	deleteCalls []core.DeleteSecretInput
	listSecrets []core.Secret
	err         error
}

func (s *fakeVaultService) CreateSecret(_ context.Context, _ core.Session, input core.CreateSecretInput) (core.Secret, error) {
	s.createCalls = append(s.createCalls, input)
	if s.err != nil {
		return core.Secret{}, s.err
	}
	return core.Secret{ID: "created-id", Type: input.Type, Metadata: input.Metadata, Payload: input.Payload, PayloadSchemaVersion: input.PayloadSchemaVersion, Version: 1}, nil
}

func (s *fakeVaultService) GetSecret(_ context.Context, _ core.Session, input core.GetSecretInput) (core.Secret, error) {
	if s.err != nil {
		return core.Secret{}, s.err
	}
	for _, secret := range s.listSecrets {
		if secret.ID == input.ID {
			return secret, nil
		}
	}
	return core.Secret{}, nil
}

func (s *fakeVaultService) ListSecrets(context.Context, core.Session, core.ListSecretsInput) ([]core.Secret, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.listSecrets, nil
}

func (s *fakeVaultService) UpdateSecret(_ context.Context, _ core.Session, input core.UpdateSecretInput) (core.Secret, error) {
	s.updateCalls = append(s.updateCalls, input)
	if s.err != nil {
		return core.Secret{}, s.err
	}
	return core.Secret{ID: input.ID, Type: input.Type, Metadata: input.Metadata, Payload: input.Payload, PayloadSchemaVersion: input.PayloadSchemaVersion, Version: input.ExpectedVersion + 1}, nil
}

func (s *fakeVaultService) DeleteSecret(_ context.Context, _ core.Session, input core.DeleteSecretInput) (core.DeleteSecretResult, error) {
	s.deleteCalls = append(s.deleteCalls, input)
	if s.err != nil {
		return core.DeleteSecretResult{}, s.err
	}
	return core.DeleteSecretResult{ID: input.ID, Version: input.ExpectedVersion + 1, DeletedAt: time.Now()}, nil
}

func (s *fakeVaultService) SyncSecrets(context.Context, core.Session, core.SyncSecretsInput) (core.SyncSecretsResult, error) {
	if s.err != nil {
		return core.SyncSecretsResult{}, s.err
	}
	return core.SyncSecretsResult{Secrets: s.listSecrets, NextChangedAfter: time.Now()}, nil
}

func TestAuthDoneOpensVaultAndLoadsList(t *testing.T) {
	session := testSession()
	vaultService := &fakeVaultService{
		listSecrets: []core.Secret{testTextSecret(t)},
	}
	state := clientapp.NewSessionState()
	m := newModel(context.Background(), appDeps{
		authService:  &fakeAuthService{session: session},
		vaultService: vaultService,
		sessionState: state,
	})

	updated, cmd := m.Update(authDoneMsg{session: session})
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("authDoneMsg command = nil, want list command")
	}

	if m.screen != screenList {
		t.Fatalf("screen = %v, want screenList", m.screen)
	}

	if _, ok := state.Session(); !ok {
		t.Fatalf("session state is not open")
	}

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(model)

	if len(m.secrets) != 1 {
		t.Fatalf("secrets length = %d, want 1", len(m.secrets))
	}
}

func TestOTPFormBuildsCreateSecretInput(t *testing.T) {
	m := newModel(context.Background(), appDeps{})
	updated, _ := m.startCreateForm(secretKindOTP)
	m = updated.(model)
	m.inputs[0].SetValue("Example OTP")
	m.inputs[1].SetValue("Example")
	m.inputs[2].SetValue("user@example.com")
	m.inputs[3].SetValue("BASE32SECRET")
	m.inputs[4].SetValue("6")
	m.inputs[5].SetValue("30")
	m.inputs[6].SetValue("sha1")
	m.inputs[7].SetValue("work")

	input, err := m.secretInputFromForm()
	if err != nil {
		t.Fatalf("secretInputFromForm() error = %v", err)
	}

	if input.Type != core.SecretTypeOTP {
		t.Fatalf("Type = %v, want SecretTypeOTP", input.Type)
	}

	otpPayload, err := core.DecodeOTPPayload(input.Payload, input.PayloadSchemaVersion)
	if err != nil {
		t.Fatalf("DecodeOTPPayload() error = %v", err)
	}

	if otpPayload.Algorithm != "SHA1" {
		t.Fatalf("Algorithm = %q, want SHA1", otpPayload.Algorithm)
	}
}

func TestSaveBinaryCommandWritesFile(t *testing.T) {
	payload, version, err := core.EncodeBinaryPayload(core.BinaryPayload{
		FileName: "secret.bin",
		Data:     []byte("binary payload"),
	})
	if err != nil {
		t.Fatalf("EncodeBinaryPayload() error = %v", err)
	}

	m := newModel(context.Background(), appDeps{})
	outputPath := filepath.Join(t.TempDir(), "secret.bin")
	cmd := m.saveBinaryCmd(core.Secret{
		Type:                 core.SecretTypeBinary,
		Payload:              payload,
		PayloadSchemaVersion: version,
	}, outputPath)

	msg := cmd().(saveDoneMsg)
	if msg.err != nil {
		t.Fatalf("saveBinaryCmd() error = %v", msg.err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if !bytes.Equal(data, []byte("binary payload")) {
		t.Fatalf("saved data = %q, want binary payload", data)
	}
}

func TestStartUpdateOTPFormPrepopulatesFields(t *testing.T) {
	payload, version, err := core.EncodeOTPPayload(core.OTPPayload{
		Issuer:        "Example",
		AccountName:   "user@example.com",
		Secret:        "BASE32SECRET",
		Algorithm:     "SHA256",
		Digits:        8,
		PeriodSeconds: 45,
		Notes:         "work",
	})
	if err != nil {
		t.Fatalf("EncodeOTPPayload() error = %v", err)
	}

	metadata, err := encodeTextSecretMetadata("Example OTP")
	if err != nil {
		t.Fatalf("encodeTextSecretMetadata() error = %v", err)
	}

	m := newModel(context.Background(), appDeps{})
	updated, _ := m.startUpdateForm(core.Secret{
		ID:                   "otp-id",
		Type:                 core.SecretTypeOTP,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: version,
		Version:              3,
	})
	m = updated.(model)

	if m.formMode != formModeUpdate {
		t.Fatalf("formMode = %v, want update", m.formMode)
	}

	if m.inputs[6].Value() != "SHA256" {
		t.Fatalf("algorithm input = %q, want SHA256", m.inputs[6].Value())
	}

	if m.editID != "otp-id" || m.editVer != 3 {
		t.Fatalf("edit state = %q/%d, want otp-id/3", m.editID, m.editVer)
	}
}

func testSession() core.Session {
	return core.Session{
		AccessToken:          "access-token",
		AccessTokenExpiresAt: time.Now().Add(time.Hour),
		VaultKey:             bytes.Repeat([]byte{1}, 32),
	}
}

func testTextSecret(t *testing.T) core.Secret {
	t.Helper()
	metadata, err := encodeTextSecretMetadata("Text secret")
	if err != nil {
		t.Fatalf("encodeTextSecretMetadata() error = %v", err)
	}
	payload, version, err := core.EncodeTextPayload(core.TextPayload{Text: "secret"})
	if err != nil {
		t.Fatalf("EncodeTextPayload() error = %v", err)
	}
	return core.Secret{
		ID:                   "text-id",
		Type:                 core.SecretTypeText,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: version,
		Version:              1,
	}
}
