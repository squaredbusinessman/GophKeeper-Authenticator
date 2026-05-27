package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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
	syncCalls   []core.SyncSecretsInput
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
	s.syncCalls = append(s.syncCalls, core.SyncSecretsInput{})
	if s.err != nil {
		return core.SyncSecretsResult{}, s.err
	}
	return core.SyncSecretsResult{Secrets: s.listSecrets, NextChangedAfter: time.Now()}, nil
}

type fakeBlobService struct {
	uploadBinaryFunc   func(context.Context, core.Session, core.UploadBinaryInput) (core.BinaryPayload, error)
	downloadBinaryFunc func(context.Context, core.Session, core.DownloadBinaryInput) ([]byte, error)
	uploadBinaryCalls  []core.UploadBinaryInput
	downloadCalls      []core.DownloadBinaryInput
}

func (s *fakeBlobService) UploadBinary(ctx context.Context, session core.Session, input core.UploadBinaryInput) (core.BinaryPayload, error) {
	s.uploadBinaryCalls = append(s.uploadBinaryCalls, input)
	if s.uploadBinaryFunc != nil {
		return s.uploadBinaryFunc(ctx, session, input)
	}
	return core.BinaryPayload{
		FileName:       input.FileName,
		ContentType:    input.ContentType,
		SizeBytes:      int64(len(input.Data)),
		ChecksumSHA256: "checksum",
		BlobID:         "blob-id",
	}, nil
}

func (s *fakeBlobService) DownloadBinary(ctx context.Context, session core.Session, input core.DownloadBinaryInput) ([]byte, error) {
	s.downloadCalls = append(s.downloadCalls, input)
	if s.downloadBinaryFunc != nil {
		return s.downloadBinaryFunc(ctx, session, input)
	}
	return []byte("binary payload"), nil
}

func TestWelcomeScreenShowsBannerAndCommands(t *testing.T) {
	m := newModel(context.Background(), appDeps{})

	if m.screen != screenWelcome {
		t.Fatalf("screen = %v, want screenWelcome", m.screen)
	}

	view := m.View()
	for _, want := range []string{"____  ___", "Команды", "Enter  перейти к входу", "T/P/C/B/O"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view = %q, want %q", view, want)
		}
	}

	updated, cmd := m.Update(keyEnter())
	m = updated.(model)
	if cmd != nil {
		t.Fatalf("welcome enter command = %v, want nil", cmd)
	}
	if m.screen != screenAuth {
		t.Fatalf("screen = %v, want screenAuth", m.screen)
	}
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

func TestTUIAuthFlowThroughModelUpdate(t *testing.T) {
	session := testSession()
	authService := &fakeAuthService{session: session}
	vaultService := &fakeVaultService{listSecrets: []core.Secret{testTextSecret(t)}}
	state := clientapp.NewSessionState()
	m := newModel(context.Background(), appDeps{
		authService:  authService,
		vaultService: vaultService,
		sessionState: state,
	})
	m.screen = screenAuth

	m.inputs[0].SetValue(" user@example.com ")
	m.inputs[1].SetValue("login-password")
	m.inputs[2].SetValue("master-password")
	m.focus = 2

	updated, cmd := m.Update(keyEnter())
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("login enter command = nil")
	}
	if !m.busy {
		t.Fatalf("busy = false, want true while login is running")
	}

	msg := cmd()
	updated, cmd = m.Update(msg)
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("authDone command = nil, want list command")
	}
	if len(authService.loginCalls) != 1 {
		t.Fatalf("login calls = %d, want 1", len(authService.loginCalls))
	}
	if authService.loginCalls[0].Login != "user@example.com" {
		t.Fatalf("login = %q, want trimmed login", authService.loginCalls[0].Login)
	}

	updated, _ = m.Update(cmd())
	m = updated.(model)
	if m.screen != screenList {
		t.Fatalf("screen = %v, want screenList", m.screen)
	}
	if len(m.secrets) != 1 {
		t.Fatalf("secrets length = %d, want 1", len(m.secrets))
	}
}

func TestTUIFunctionalCreateOTPAndRenderCurrentCode(t *testing.T) {
	session := testSession()
	state := clientapp.NewSessionState()
	if err := state.SetSession(session); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	vaultService := &fakeVaultService{}
	m := newModel(context.Background(), appDeps{
		vaultService: vaultService,
		sessionState: state,
	})
	m.screen = screenList

	updated, _ := m.Update(keyRune('n'))
	m = updated.(model)
	if m.screen != screenTypeSelect {
		t.Fatalf("screen = %v, want screenTypeSelect", m.screen)
	}

	updated, _ = m.Update(keyRune('o'))
	m = updated.(model)
	if m.screen != screenForm || m.formKind != secretKindOTP {
		t.Fatalf("screen/kind = %v/%s, want otp form", m.screen, m.formKind)
	}

	m.inputs[0].SetValue("Example OTP")
	m.inputs[1].SetValue("Example")
	m.inputs[2].SetValue("user@example.com")
	m.inputs[3].SetValue("JBSWY3DPEHPK3PXP")
	m.inputs[4].SetValue("6")
	m.inputs[5].SetValue("30")
	m.inputs[6].SetValue("SHA1")
	m.inputs[7].SetValue("work")
	m.focus = 7

	updated, cmd := m.Update(keyEnter())
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("create otp command = nil")
	}

	createdMsg := cmd()
	updated, cmd = m.Update(createdMsg)
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("secretDone command = nil, want list reload")
	}
	if len(vaultService.createCalls) != 1 {
		t.Fatalf("create calls = %d, want 1", len(vaultService.createCalls))
	}
	if vaultService.createCalls[0].Type != core.SecretTypeOTP {
		t.Fatalf("created type = %v, want OTP", vaultService.createCalls[0].Type)
	}

	view := m.View()
	if !strings.Contains(view, "Текущий OTP-код:") {
		t.Fatalf("view does not contain OTP code: %q", view)
	}
	if strings.Contains(view, "JBSWY3DPEHPK3PXP") {
		t.Fatalf("view contains raw OTP secret")
	}
}

func TestOTPTickRefreshesDetailAndSchedulesNextTick(t *testing.T) {
	payload, version, err := core.EncodeOTPPayload(core.OTPPayload{
		Issuer:        "Example",
		AccountName:   "user@example.com",
		Secret:        "JBSWY3DPEHPK3PXP",
		Algorithm:     "SHA1",
		Digits:        6,
		PeriodSeconds: 30,
	})
	if err != nil {
		t.Fatalf("EncodeOTPPayload() error = %v", err)
	}

	metadata, err := encodeTextSecretMetadata("Example OTP")
	if err != nil {
		t.Fatalf("encodeTextSecretMetadata() error = %v", err)
	}

	secret := core.Secret{
		ID:                   "otp-id",
		Type:                 core.SecretTypeOTP,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: version,
		Version:              1,
	}
	m := newModel(context.Background(), appDeps{})
	m.screen = screenDetail
	m.current = &secret

	updated, cmd := m.Update(otpTickMsg(time.Now()))
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("otp tick command = nil, want next tick")
	}

	if !strings.Contains(m.detail.View(), "Текущий OTP-код:") {
		t.Fatalf("detail = %q, want current otp code", m.detail.View())
	}
}

func TestTUISyncAfterDeleteFlow(t *testing.T) {
	session := testSession()
	state := clientapp.NewSessionState()
	if err := state.SetSession(session); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	secret := testTextSecret(t)
	vaultService := &fakeVaultService{listSecrets: []core.Secret{secret}}
	m := newModel(context.Background(), appDeps{
		vaultService: vaultService,
		sessionState: state,
	})
	m.screen = screenList
	m.secrets = []core.Secret{secret}

	updated, _ := m.Update(keyRune('d'))
	m = updated.(model)
	if m.screen != screenDelete {
		t.Fatalf("screen = %v, want screenDelete", m.screen)
	}

	updated, cmd := m.Update(keyRune('y'))
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("delete command = nil")
	}
	if !m.busy {
		t.Fatalf("busy = false, want true while delete is running")
	}

	updated, cmd = m.Update(cmd())
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("deleteDone command = nil, want list reload")
	}
	if len(vaultService.deleteCalls) != 1 {
		t.Fatalf("delete calls = %d, want 1", len(vaultService.deleteCalls))
	}

	updated, _ = m.Update(cmd())
	m = updated.(model)
	updated, cmd = m.Update(keyRune('s'))
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("sync command = nil")
	}

	updated, cmd = m.Update(cmd())
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("syncDone command = nil, want list reload")
	}
	if len(vaultService.syncCalls) != 1 {
		t.Fatalf("sync calls = %d, want 1", len(vaultService.syncCalls))
	}
}

func TestListQuitReturnsToWelcomeAndClearsSession(t *testing.T) {
	state := clientapp.NewSessionState()
	if err := state.SetSession(testSession()); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	m := newModel(context.Background(), appDeps{sessionState: state})
	m.screen = screenList
	m.secrets = []core.Secret{testTextSecret(t)}
	m.current = &m.secrets[0]
	m.statusOK("vault открыт")

	updated, cmd := m.Update(keyRune('q'))
	m = updated.(model)
	if cmd != nil {
		t.Fatalf("quit command = %v, want nil", cmd)
	}
	if m.screen != screenWelcome {
		t.Fatalf("screen = %v, want screenWelcome", m.screen)
	}
	if _, ok := state.Session(); ok {
		t.Fatalf("session is still open")
	}
	if len(m.secrets) != 0 {
		t.Fatalf("secrets length = %d, want 0", len(m.secrets))
	}
	if m.current != nil {
		t.Fatalf("current = %+v, want nil", m.current)
	}
}

func TestTUIFormValidationReturnsErrors(t *testing.T) {
	tests := []struct {
		name   string
		kind   secretKind
		fill   func([]textinput.Model)
		errMsg string
	}{
		{
			name: "missing title",
			kind: secretKindText,
			fill: func(inputs []textinput.Model) {
				inputs[1].SetValue("secret")
			},
			errMsg: "title is required",
		},
		{
			name: "otp invalid digits",
			kind: secretKindOTP,
			fill: func(inputs []textinput.Model) {
				inputs[0].SetValue("OTP")
				inputs[3].SetValue("JBSWY3DPEHPK3PXP")
				inputs[4].SetValue("7")
				inputs[6].SetValue("SHA1")
			},
			errMsg: "otp digits must be 6 or 8",
		},
		{
			name: "otp invalid period",
			kind: secretKindOTP,
			fill: func(inputs []textinput.Model) {
				inputs[0].SetValue("OTP")
				inputs[3].SetValue("JBSWY3DPEHPK3PXP")
				inputs[4].SetValue("6")
				inputs[5].SetValue("not-number")
				inputs[6].SetValue("SHA1")
			},
			errMsg: "parse otp period",
		},
		{
			name: "binary missing file",
			kind: secretKindBinary,
			fill: func(inputs []textinput.Model) {
				inputs[0].SetValue("Binary")
				inputs[1].SetValue(filepath.Join(t.TempDir(), "missing.bin"))
			},
			errMsg: "read binary file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := appDeps{}
			if tt.kind == secretKindBinary {
				state := clientapp.NewSessionState()
				if err := state.SetSession(testSession()); err != nil {
					t.Fatalf("SetSession() error = %v", err)
				}
				deps.blobService = &fakeBlobService{}
				deps.sessionState = state
			}
			m := newModel(context.Background(), deps)
			updated, _ := m.startCreateForm(tt.kind)
			m = updated.(model)
			tt.fill(m.inputs)

			_, err := m.secretInputFromForm()
			if err == nil {
				t.Fatalf("secretInputFromForm() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestSaveBinaryCommandWritesFile(t *testing.T) {
	payload, version, err := core.EncodeBinaryPayload(core.BinaryPayload{
		FileName:       "secret.bin",
		SizeBytes:      int64(len("binary payload")),
		ChecksumSHA256: "checksum",
		BlobID:         "blob-id",
	})
	if err != nil {
		t.Fatalf("EncodeBinaryPayload() error = %v", err)
	}

	state := clientapp.NewSessionState()
	if err := state.SetSession(testSession()); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	blobService := &fakeBlobService{}
	m := newModel(context.Background(), appDeps{
		blobService:  blobService,
		sessionState: state,
	})
	outputDir := filepath.Join(t.TempDir(), "output")
	cmd := m.saveBinaryCmd(core.Secret{
		Type:                 core.SecretTypeBinary,
		Payload:              payload,
		PayloadSchemaVersion: version,
	}, outputDir)

	msg := cmd().(saveDoneMsg)
	if msg.err != nil {
		t.Fatalf("saveBinaryCmd() error = %v", msg.err)
	}

	outputPath := filepath.Join(outputDir, "secret.bin")
	if msg.path != outputPath {
		t.Fatalf("saved path = %q, want %q", msg.path, outputPath)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if !bytes.Equal(data, []byte("binary payload")) {
		t.Fatalf("saved data = %q, want binary payload", data)
	}
	if len(blobService.downloadCalls) != 1 {
		t.Fatalf("DownloadBinary() calls = %d, want 1", len(blobService.downloadCalls))
	}
}

func TestSaveBinaryCommandWritesFileInsideExistingDirectory(t *testing.T) {
	payload, version, err := core.EncodeBinaryPayload(core.BinaryPayload{
		FileName:       "secret.bin",
		SizeBytes:      int64(len("binary payload")),
		ChecksumSHA256: "checksum",
		BlobID:         "blob-id",
	})
	if err != nil {
		t.Fatalf("EncodeBinaryPayload() error = %v", err)
	}

	state := clientapp.NewSessionState()
	if err := state.SetSession(testSession()); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	m := newModel(context.Background(), appDeps{
		blobService:  &fakeBlobService{},
		sessionState: state,
	})
	outputDir := t.TempDir()
	cmd := m.saveBinaryCmd(core.Secret{
		Type:                 core.SecretTypeBinary,
		Payload:              payload,
		PayloadSchemaVersion: version,
	}, outputDir)

	msg := cmd().(saveDoneMsg)
	if msg.err != nil {
		t.Fatalf("saveBinaryCmd() error = %v", msg.err)
	}

	outputPath := filepath.Join(outputDir, "secret.bin")
	if msg.path != outputPath {
		t.Fatalf("saved path = %q, want %q", msg.path, outputPath)
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

func TestDetailActionsUpdateDeleteSaveBinaryAndBack(t *testing.T) {
	secret := testBinarySecret(t)
	state := clientapp.NewSessionState()
	if err := state.SetSession(testSession()); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	m := newModel(context.Background(), appDeps{
		blobService:  &fakeBlobService{},
		sessionState: state,
	})
	m.screen = screenDetail
	m.current = &secret
	m.detail.SetContent(m.renderSecretDetail(secret))

	updated, _ := m.Update(keyRune('s'))
	m = updated.(model)
	if m.screen != screenSaveBinary {
		t.Fatalf("screen = %v, want screenSaveBinary", m.screen)
	}
	if len(m.inputs) != 1 || !strings.Contains(m.inputs[0].Prompt, "Папка для сохранения") {
		t.Fatalf("save inputs = %+v, want output path input", m.inputs)
	}

	outputPath := filepath.Join(t.TempDir(), "nested", "secret.bin")
	m.inputs[0].SetValue(outputPath)
	updated, cmd := m.Update(keyEnter())
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("save enter command = nil")
	}
	updated, _ = m.Update(cmd())
	m = updated.(model)
	if m.screen != screenDetail {
		t.Fatalf("screen = %v, want screenDetail after save", m.screen)
	}
	if !strings.Contains(m.status, "binary сохранен") {
		t.Fatalf("status = %q, want save status", m.status)
	}

	updated, _ = m.Update(keyRune('u'))
	m = updated.(model)
	if m.screen != screenForm || m.formMode != formModeUpdate || m.formKind != secretKindBinary {
		t.Fatalf("update state = screen %v mode %v kind %s, want binary update form", m.screen, m.formMode, m.formKind)
	}

	m.screen = screenDetail
	m.current = &secret
	updated, _ = m.Update(keyRune('d'))
	m = updated.(model)
	if m.screen != screenDelete {
		t.Fatalf("screen = %v, want screenDelete", m.screen)
	}

	m.screen = screenDetail
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(model)
	if m.screen != screenList {
		t.Fatalf("screen = %v, want screenList after esc", m.screen)
	}
}

func TestCommandErrorsWithoutOpenSession(t *testing.T) {
	state := clientapp.NewSessionState()
	m := newModel(context.Background(), appDeps{sessionState: state})

	if msg := m.loadSecretsCmd(false)().(listDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "vault session is not open") {
		t.Fatalf("loadSecretsCmd() err = %v, want session error", msg.err)
	}
	if msg := m.getSecretCmd("id")().(secretDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "vault session is not open") {
		t.Fatalf("getSecretCmd() err = %v, want session error", msg.err)
	}
	if msg := m.syncCmd()().(syncDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "vault session is not open") {
		t.Fatalf("syncCmd() err = %v, want session error", msg.err)
	}
	if msg := m.deleteCmd(testTextSecret(t))().(deleteDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "vault session is not open") {
		t.Fatalf("deleteCmd() err = %v, want session error", msg.err)
	}
	if msg := m.submitFormCmd()().(secretDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "vault session is not open") {
		t.Fatalf("submitFormCmd() err = %v, want session error", msg.err)
	}
}

func TestAuthModeSwitchRegisterMismatchAndFocusNavigation(t *testing.T) {
	m := newModel(context.Background(), appDeps{})
	m.screen = screenAuth

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlR})
	m = updated.(model)
	if cmd != nil {
		t.Fatalf("ctrl+r command = %v, want nil", cmd)
	}
	if m.authMode != authModeRegister || len(m.inputs) != 4 {
		t.Fatalf("auth state = mode %v inputs %d, want register with 4 inputs", m.authMode, len(m.inputs))
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	m = updated.(model)
	if m.focus != len(m.inputs)-1 {
		t.Fatalf("focus = %d, want last input", m.focus)
	}

	m.inputs[0].SetValue("user@example.com")
	m.inputs[1].SetValue("login-password")
	m.inputs[2].SetValue("master-password")
	m.inputs[3].SetValue("other-master-password")
	m.focus = len(m.inputs) - 1
	updated, cmd = m.Update(keyEnter())
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("register submit command = nil")
	}
	msg := cmd().(authDoneMsg)
	if msg.err == nil || !strings.Contains(msg.err.Error(), "master passwords do not match") {
		t.Fatalf("auth error = %v, want master password mismatch", msg.err)
	}
	updated, _ = m.Update(msg)
	m = updated.(model)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlL})
	m = updated.(model)
	if m.authMode != authModeLogin || len(m.inputs) != 3 {
		t.Fatalf("auth state = mode %v inputs %d, want login with 3 inputs", m.authMode, len(m.inputs))
	}
}

func TestListNavigationAndCommands(t *testing.T) {
	session := testSession()
	state := clientapp.NewSessionState()
	if err := state.SetSession(session); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	first := testTextSecret(t)
	second := testLoginPasswordSecret(t)
	vaultService := &fakeVaultService{listSecrets: []core.Secret{first, second}}
	m := newModel(context.Background(), appDeps{
		vaultService: vaultService,
		sessionState: state,
	})
	m.screen = screenList
	m.secrets = []core.Secret{first, second}

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(model)
	if m.selected != 1 {
		t.Fatalf("selected = %d, want 1", m.selected)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = updated.(model)
	if m.selected != 0 {
		t.Fatalf("selected = %d, want 0", m.selected)
	}

	updated, cmd := m.Update(keyEnter())
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("enter command = nil, want get secret command")
	}
	updated, cmd = m.Update(cmd())
	m = updated.(model)
	if m.screen != screenDetail || m.current == nil || m.current.ID != first.ID {
		t.Fatalf("detail state = screen %v current %+v, want first secret", m.screen, m.current)
	}
	if cmd != nil {
		updated, _ = m.Update(cmd())
		m = updated.(model)
	}

	m.screen = screenList
	updated, cmd = m.Update(keyRune('r'))
	m = updated.(model)
	if cmd == nil {
		t.Fatalf("refresh command = nil")
	}
	updated, _ = m.Update(cmd())
	m = updated.(model)
	if len(m.secrets) != 2 {
		t.Fatalf("secrets length = %d, want 2", len(m.secrets))
	}
}

func TestSecretInputFromFormBuildsAllNonOTPTypes(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(filePath, []byte("file payload"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	tests := []struct {
		name       string
		kind       secretKind
		fill       func([]textinput.Model)
		secretType core.SecretType
	}{
		{
			name: "text",
			kind: secretKindText,
			fill: func(inputs []textinput.Model) {
				inputs[0].SetValue("Text")
				inputs[1].SetValue("secret text")
			},
			secretType: core.SecretTypeText,
		},
		{
			name: "login password",
			kind: secretKindLoginPassword,
			fill: func(inputs []textinput.Model) {
				inputs[0].SetValue("GitHub")
				inputs[1].SetValue("user@example.com")
				inputs[2].SetValue("password")
				inputs[3].SetValue("https://github.com")
				inputs[4].SetValue("work")
			},
			secretType: core.SecretTypeLoginPassword,
		},
		{
			name: "bank card",
			kind: secretKindBankCard,
			fill: func(inputs []textinput.Model) {
				inputs[0].SetValue("Card")
				inputs[1].SetValue("4111111111111111")
				inputs[2].SetValue("IVAN IVANOV")
				inputs[3].SetValue("05")
				inputs[4].SetValue("2030")
				inputs[5].SetValue("123")
				inputs[6].SetValue("salary")
			},
			secretType: core.SecretTypeBankCard,
		},
		{
			name: "binary",
			kind: secretKindBinary,
			fill: func(inputs []textinput.Model) {
				inputs[0].SetValue("File")
				inputs[1].SetValue(filePath)
				inputs[2].SetValue("text/plain")
			},
			secretType: core.SecretTypeBinary,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := appDeps{}
			if tt.kind == secretKindBinary {
				state := clientapp.NewSessionState()
				if err := state.SetSession(testSession()); err != nil {
					t.Fatalf("SetSession() error = %v", err)
				}
				deps.blobService = &fakeBlobService{}
				deps.sessionState = state
			}
			m := newModel(context.Background(), deps)
			updated, _ := m.startCreateForm(tt.kind)
			m = updated.(model)
			tt.fill(m.inputs)

			input, err := m.secretInputFromForm()
			if err != nil {
				t.Fatalf("secretInputFromForm() error = %v", err)
			}
			if input.Type != tt.secretType {
				t.Fatalf("Type = %v, want %v", input.Type, tt.secretType)
			}
			if len(input.Metadata) == 0 || len(input.Payload) == 0 {
				t.Fatalf("encoded input has empty metadata or payload")
			}
		})
	}
}

func TestViewsRenderExpectedScreensAndStatuses(t *testing.T) {
	otpSecret := testOTPSecret(t)
	m := newModel(context.Background(), appDeps{})
	m.screen = screenList
	m.secrets = []core.Secret{otpSecret}
	if view := m.View(); !strings.Contains(view, "Vault") || !strings.Contains(view, "otp") || !strings.Contains(view, "стартовый экран") {
		t.Fatalf("list view = %q, want vault otp row and hints", view)
	}

	m.screen = screenTypeSelect
	if view := m.View(); !strings.Contains(view, "Новый секрет") || !strings.Contains(view, "O OTP") {
		t.Fatalf("type select view = %q, want type choices", view)
	}

	updated, _ := m.startCreateForm(secretKindLoginPassword)
	m = updated.(model)
	if view := m.View(); !strings.Contains(view, "Обновление:") && !strings.Contains(view, "Создание: логин и пароль") {
		t.Fatalf("form view = %q, want login password form", view)
	}

	m.screen = screenDelete
	m.current = nil
	if view := m.View(); !strings.Contains(view, "Удалить: <unknown>") {
		t.Fatalf("delete view = %q, want unknown title", view)
	}

	m.screen = screenSaveBinary
	m.inputs = makeInputs([]string{"Папка для сохранения"}, nil)
	if view := m.View(); !strings.Contains(view, "Сохранение binary") {
		t.Fatalf("save binary view = %q, want save title", view)
	}

	m.busy = true
	if view := m.View(); !strings.Contains(view, "выполняется операция") {
		t.Fatalf("busy view = %q, want busy status", view)
	}
	m.busy = false
	m.setError(os.ErrNotExist)
	if view := m.View(); !strings.Contains(view, "file does not exist") {
		t.Fatalf("error view = %q, want user facing error", view)
	}
}

func TestInputsFromSecretPrepopulateAllTypes(t *testing.T) {
	for _, secret := range []core.Secret{
		testTextSecret(t),
		testLoginPasswordSecret(t),
		testBankCardSecret(t),
		testBinarySecret(t),
		testOTPSecret(t),
	} {
		inputs, err := inputsFromSecret(secret)
		if err != nil {
			t.Fatalf("inputsFromSecret(%v) error = %v", secret.Type, err)
		}
		if len(inputs) == 0 || inputs[0].Value() == "" {
			t.Fatalf("inputsFromSecret(%v) did not prepopulate title", secret.Type)
		}
	}

	_, err := inputsFromSecret(core.Secret{
		Type:                 core.SecretTypeText,
		Metadata:             []byte(`{"title":"broken"}`),
		Payload:              []byte(`{`),
		PayloadSchemaVersion: 1,
	})
	if err == nil {
		t.Fatalf("inputsFromSecret() error = nil, want decode error")
	}
}

func TestSaveBinaryCommandValidationErrors(t *testing.T) {
	secret := testBinarySecret(t)
	state := clientapp.NewSessionState()
	if err := state.SetSession(testSession()); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	m := newModel(context.Background(), appDeps{
		blobService:  &fakeBlobService{},
		sessionState: state,
	})

	if msg := m.saveBinaryCmd(secret, " ")().(saveDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "output directory is required") {
		t.Fatalf("empty output path err = %v, want required error", msg.err)
	}

	existingPath := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(existingPath, []byte("exists"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if msg := m.saveBinaryCmd(secret, existingPath)().(saveDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "output directory is not a directory") {
		t.Fatalf("existing path err = %v, want directory error", msg.err)
	}

	existingDir := t.TempDir()
	existingFileInDir := filepath.Join(existingDir, "secret.bin")
	if err := os.WriteFile(existingFileInDir, []byte("exists"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if msg := m.saveBinaryCmd(secret, existingDir)().(saveDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "output file already exists") {
		t.Fatalf("existing file in directory err = %v, want exists error", msg.err)
	}

	broken := secret
	broken.Payload = []byte(`{`)
	if msg := m.saveBinaryCmd(broken, filepath.Join(t.TempDir(), "broken.bin"))().(saveDoneMsg); msg.err == nil || !strings.Contains(msg.err.Error(), "decode binary payload") {
		t.Fatalf("broken payload err = %v, want decode error", msg.err)
	}
}

func TestNormalizeBinaryOutputPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skipf("UserHomeDir() = %q, %v", home, err)
	}

	got, err := normalizeBinaryOutputPath("~/secret.bin")
	if err != nil {
		t.Fatalf("normalizeBinaryOutputPath() error = %v", err)
	}
	if want := filepath.Join(home, "secret.bin"); got != want {
		t.Fatalf("tilde path = %q, want %q", got, want)
	}

	got, err = normalizeBinaryOutputPath("~")
	if err != nil {
		t.Fatalf("normalizeBinaryOutputPath() error = %v", err)
	}
	if want := filepath.Clean(home); got != want {
		t.Fatalf("home shorthand path = %q, want %q", got, want)
	}

	homeWithoutRoot := strings.TrimPrefix(filepath.Clean(home), string(os.PathSeparator))
	got, err = normalizeBinaryOutputPath(filepath.Join(homeWithoutRoot, "secret.bin"))
	if err != nil {
		t.Fatalf("normalizeBinaryOutputPath() error = %v", err)
	}
	if want := filepath.Join(home, "secret.bin"); got != want {
		t.Fatalf("home path without leading slash = %q, want %q", got, want)
	}

	got, err = normalizeBinaryOutputPath(filepath.Join(home, homeWithoutRoot, "secret.bin"))
	if err != nil {
		t.Fatalf("normalizeBinaryOutputPath() error = %v", err)
	}
	if want := filepath.Join(home, "secret.bin"); got != want {
		t.Fatalf("duplicated home path = %q, want %q", got, want)
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

func testLoginPasswordSecret(t *testing.T) core.Secret {
	t.Helper()
	metadata, err := encodeTextSecretMetadata("Login secret")
	if err != nil {
		t.Fatalf("encodeTextSecretMetadata() error = %v", err)
	}
	payload, version, err := core.EncodeLoginPasswordPayload(core.LoginPasswordPayload{
		Login:    "user@example.com",
		Password: "password",
		URL:      "https://example.com",
		Notes:    "work",
	})
	if err != nil {
		t.Fatalf("EncodeLoginPasswordPayload() error = %v", err)
	}
	return core.Secret{
		ID:                   "login-id",
		Type:                 core.SecretTypeLoginPassword,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: version,
		Version:              2,
	}
}

func testBankCardSecret(t *testing.T) core.Secret {
	t.Helper()
	metadata, err := encodeTextSecretMetadata("Card secret")
	if err != nil {
		t.Fatalf("encodeTextSecretMetadata() error = %v", err)
	}
	payload, version, err := core.EncodeBankCardPayload(core.BankCardPayload{
		Number:          "4111111111111111",
		CardholderName:  "IVAN IVANOV",
		ExpirationMonth: "05",
		ExpirationYear:  "2030",
		CVV:             "123",
		Notes:           "salary",
	})
	if err != nil {
		t.Fatalf("EncodeBankCardPayload() error = %v", err)
	}
	return core.Secret{
		ID:                   "card-id",
		Type:                 core.SecretTypeBankCard,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: version,
		Version:              3,
	}
}

func testBinarySecret(t *testing.T) core.Secret {
	t.Helper()
	metadata, err := encodeTextSecretMetadata("Binary secret")
	if err != nil {
		t.Fatalf("encodeTextSecretMetadata() error = %v", err)
	}
	payload, version, err := core.EncodeBinaryPayload(core.BinaryPayload{
		FileName:       "secret.bin",
		ContentType:    "application/octet-stream",
		SizeBytes:      int64(len("binary payload")),
		ChecksumSHA256: "checksum",
		BlobID:         "blob-id",
	})
	if err != nil {
		t.Fatalf("EncodeBinaryPayload() error = %v", err)
	}
	return core.Secret{
		ID:                   "binary-id",
		Type:                 core.SecretTypeBinary,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: version,
		Version:              4,
	}
}

func testOTPSecret(t *testing.T) core.Secret {
	t.Helper()
	metadata, err := encodeTextSecretMetadata("OTP secret")
	if err != nil {
		t.Fatalf("encodeTextSecretMetadata() error = %v", err)
	}
	payload, version, err := core.EncodeOTPPayload(core.OTPPayload{
		Issuer:        "Example",
		AccountName:   "user@example.com",
		Secret:        "JBSWY3DPEHPK3PXP",
		Algorithm:     "SHA1",
		Digits:        6,
		PeriodSeconds: 30,
		Notes:         "work",
	})
	if err != nil {
		t.Fatalf("EncodeOTPPayload() error = %v", err)
	}
	return core.Secret{
		ID:                   "otp-id",
		Type:                 core.SecretTypeOTP,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: version,
		Version:              5,
	}
}

func keyEnter() tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyEnter}
}

func keyRune(value rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{value}}
}
