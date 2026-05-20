package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
)

type fakeCLIVaultService struct {
	createSecretFunc func(context.Context, core.Session, core.CreateSecretInput) (core.Secret, error)
	getSecretFunc    func(context.Context, core.Session, core.GetSecretInput) (core.Secret, error)
	listSecretsFunc  func(context.Context, core.Session, core.ListSecretsInput) ([]core.Secret, error)
	updateSecretFunc func(context.Context, core.Session, core.UpdateSecretInput) (core.Secret, error)
	deleteSecretFunc func(context.Context, core.Session, core.DeleteSecretInput) (core.DeleteSecretResult, error)
	syncSecretsFunc  func(context.Context, core.Session, core.SyncSecretsInput) (core.SyncSecretsResult, error)

	createSecretCalls []createSecretCall
	getSecretCalls    []getSecretCall
	listSecretsCalls  []listSecretsCall
	updateSecretCalls []updateSecretCall
	deleteSecretCalls []deleteSecretCall
	syncSecretsCalls  []syncSecretsCall
}

type createSecretCall struct {
	session core.Session
	input   core.CreateSecretInput
}

type getSecretCall struct {
	session core.Session
	input   core.GetSecretInput
}

type listSecretsCall struct {
	session core.Session
	input   core.ListSecretsInput
}

type updateSecretCall struct {
	session core.Session
	input   core.UpdateSecretInput
}

type deleteSecretCall struct {
	session core.Session
	input   core.DeleteSecretInput
}

type syncSecretsCall struct {
	session core.Session
	input   core.SyncSecretsInput
}

func (s *fakeCLIVaultService) CreateSecret(ctx context.Context, session core.Session, input core.CreateSecretInput) (core.Secret, error) {
	s.createSecretCalls = append(s.createSecretCalls, createSecretCall{
		session: session,
		input:   input,
	})
	if s.createSecretFunc != nil {
		return s.createSecretFunc(ctx, session, input)
	}

	return core.Secret{
		ID:                   "text-secret-id",
		Type:                 core.SecretTypeText,
		Metadata:             input.Metadata,
		Payload:              input.Payload,
		PayloadSchemaVersion: input.PayloadSchemaVersion,
		Version:              1,
		CreatedAt:            time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC),
		UpdatedAt:            time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC),
	}, nil
}

func (s *fakeCLIVaultService) GetSecret(ctx context.Context, session core.Session, input core.GetSecretInput) (core.Secret, error) {
	s.getSecretCalls = append(s.getSecretCalls, getSecretCall{
		session: session,
		input:   input,
	})
	if s.getSecretFunc != nil {
		return s.getSecretFunc(ctx, session, input)
	}

	return core.Secret{
		ID:                   input.ID,
		Type:                 core.SecretTypeText,
		Metadata:             []byte(`{"title":"work note"}`),
		Payload:              []byte("secret text"),
		PayloadSchemaVersion: 1,
		Version:              2,
	}, nil
}

func (s *fakeCLIVaultService) ListSecrets(ctx context.Context, session core.Session, input core.ListSecretsInput) ([]core.Secret, error) {
	s.listSecretsCalls = append(s.listSecretsCalls, listSecretsCall{
		session: session,
		input:   input,
	})
	if s.listSecretsFunc != nil {
		return s.listSecretsFunc(ctx, session, input)
	}

	deletedAt := time.Date(2026, 5, 20, 11, 0, 0, 0, time.UTC)

	return []core.Secret{
		{
			ID:                   "active-secret-id",
			Type:                 core.SecretTypeText,
			Metadata:             []byte(`{"title":"active note"}`),
			Payload:              []byte("active secret"),
			PayloadSchemaVersion: 1,
			Version:              2,
		},
		{
			ID:                   "deleted-secret-id",
			Type:                 core.SecretTypeText,
			Metadata:             []byte(`{"title":"deleted note"}`),
			Payload:              []byte("deleted secret"),
			PayloadSchemaVersion: 1,
			Version:              3,
			DeletedAt:            &deletedAt,
		},
	}, nil
}

func (s *fakeCLIVaultService) UpdateSecret(ctx context.Context, session core.Session, input core.UpdateSecretInput) (core.Secret, error) {
	s.updateSecretCalls = append(s.updateSecretCalls, updateSecretCall{
		session: session,
		input:   input,
	})
	if s.updateSecretFunc != nil {
		return s.updateSecretFunc(ctx, session, input)
	}

	return core.Secret{
		ID:                   input.ID,
		Type:                 input.Type,
		Metadata:             input.Metadata,
		Payload:              input.Payload,
		PayloadSchemaVersion: input.PayloadSchemaVersion,
		Version:              input.ExpectedVersion + 1,
	}, nil
}

func (s *fakeCLIVaultService) DeleteSecret(ctx context.Context, session core.Session, input core.DeleteSecretInput) (core.DeleteSecretResult, error) {
	s.deleteSecretCalls = append(s.deleteSecretCalls, deleteSecretCall{
		session: session,
		input:   input,
	})
	if s.deleteSecretFunc != nil {
		return s.deleteSecretFunc(ctx, session, input)
	}

	return core.DeleteSecretResult{
		ID:        input.ID,
		Version:   input.ExpectedVersion + 1,
		DeletedAt: time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
	}, nil
}

func (s *fakeCLIVaultService) SyncSecrets(ctx context.Context, session core.Session, input core.SyncSecretsInput) (core.SyncSecretsResult, error) {
	s.syncSecretsCalls = append(s.syncSecretsCalls, syncSecretsCall{
		session: session,
		input:   input,
	})
	if s.syncSecretsFunc != nil {
		return s.syncSecretsFunc(ctx, session, input)
	}

	deletedAt := time.Date(2026, 5, 20, 11, 0, 0, 0, time.UTC)
	nextChangedAfter := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	return core.SyncSecretsResult{
		Secrets: []core.Secret{
			{
				ID:                   "active-secret-id",
				Type:                 core.SecretTypeText,
				Metadata:             []byte(`{"title":"active note"}`),
				Payload:              []byte("active secret"),
				PayloadSchemaVersion: 1,
				Version:              2,
			},
			{
				ID:                   "deleted-secret-id",
				Type:                 core.SecretTypeText,
				Metadata:             []byte(`{"title":"deleted note"}`),
				Payload:              []byte("deleted secret"),
				PayloadSchemaVersion: 1,
				Version:              3,
				DeletedAt:            &deletedAt,
			},
		},
		NextChangedAfter: nextChangedAfter,
	}, nil
}

func TestCreateTextSecretCommandLogsInPromptsSecretHiddenAndCallsVaultService(t *testing.T) {
	authService := &fakeCLIAuthService{}
	vaultService := &fakeCLIVaultService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
			"work note",
			"secret text",
		},
	}
	var stdout bytes.Buffer

	err := runCLI(context.Background(), []string{"create"}, authService, vaultService, prompter, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}

	if len(authService.loginCalls) != 1 {
		t.Fatalf("Login() calls = %d, want 1", len(authService.loginCalls))
	}

	if len(vaultService.createSecretCalls) != 1 {
		t.Fatalf("CreateSecret() calls = %d, want 1", len(vaultService.createSecretCalls))
	}

	call := vaultService.createSecretCalls[0]
	if call.session.AccessToken != "access-token" {
		t.Fatalf("session access token = %q, want access-token", call.session.AccessToken)
	}

	if call.input.Type != core.SecretTypeText {
		t.Fatalf("secret type = %v, want text", call.input.Type)
	}

	if !strings.Contains(string(call.input.Metadata), "work note") {
		t.Fatalf("metadata = %q, want title", call.input.Metadata)
	}

	if string(call.input.Payload) != "secret text" {
		t.Fatalf("payload = %q, want secret text", call.input.Payload)
	}

	if call.input.PayloadSchemaVersion != 1 {
		t.Fatalf("payload schema version = %d, want 1", call.input.PayloadSchemaVersion)
	}

	wantHidden := []bool{false, true, true, false, true}
	if len(prompter.hidden) != len(wantHidden) {
		t.Fatalf("hidden prompts = %v, want %v", prompter.hidden, wantHidden)
	}

	for i := range wantHidden {
		if prompter.hidden[i] != wantHidden[i] {
			t.Fatalf("hidden prompt[%d] = %v, want %v", i, prompter.hidden[i], wantHidden[i])
		}
	}

	if !strings.Contains(stdout.String(), "text-secret-id") {
		t.Fatalf("stdout = %q, want created secret id", stdout.String())
	}
}

func TestGetTextSecretCommandLogsInPromptsIDAndPrintsSecret(t *testing.T) {
	authService := &fakeCLIAuthService{}
	vaultService := &fakeCLIVaultService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
			"text-secret-id",
		},
	}
	var stdout bytes.Buffer

	err := runCLI(context.Background(), []string{"get"}, authService, vaultService, prompter, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}

	if len(authService.loginCalls) != 1 {
		t.Fatalf("Login() calls = %d, want 1", len(authService.loginCalls))
	}

	if len(vaultService.getSecretCalls) != 1 {
		t.Fatalf("GetSecret() calls = %d, want 1", len(vaultService.getSecretCalls))
	}

	call := vaultService.getSecretCalls[0]
	if call.input.ID != "text-secret-id" {
		t.Fatalf("secret id = %q, want text-secret-id", call.input.ID)
	}

	wantHidden := []bool{false, true, true, false}
	if len(prompter.hidden) != len(wantHidden) {
		t.Fatalf("hidden prompts = %v, want %v", prompter.hidden, wantHidden)
	}

	for i := range wantHidden {
		if prompter.hidden[i] != wantHidden[i] {
			t.Fatalf("hidden prompt[%d] = %v, want %v", i, prompter.hidden[i], wantHidden[i])
		}
	}

	if !strings.Contains(stdout.String(), "secret text") {
		t.Fatalf("stdout = %q, want secret payload", stdout.String())
	}
}

func TestListTextSecretsCommandLogsInAndPrintsOnlyActiveSecrets(t *testing.T) {
	authService := &fakeCLIAuthService{}
	vaultService := &fakeCLIVaultService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
		},
	}
	var stdout bytes.Buffer

	err := runCLI(context.Background(), []string{"list"}, authService, vaultService, prompter, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}

	if len(authService.loginCalls) != 1 {
		t.Fatalf("Login() calls = %d, want 1", len(authService.loginCalls))
	}

	if len(vaultService.listSecretsCalls) != 1 {
		t.Fatalf("ListSecrets() calls = %d, want 1", len(vaultService.listSecretsCalls))
	}

	if vaultService.listSecretsCalls[0].input.IncludeDeleted {
		t.Fatalf("IncludeDeleted = true, want false")
	}

	if !strings.Contains(stdout.String(), "active-secret-id") {
		t.Fatalf("stdout = %q, want active secret id", stdout.String())
	}

	if strings.Contains(stdout.String(), "deleted-secret-id") {
		t.Fatalf("stdout = %q, want deleted secret to be hidden from active list", stdout.String())
	}
}

func TestUpdateTextSecretCommandPromptsVersionAndSecretHidden(t *testing.T) {
	authService := &fakeCLIAuthService{}
	vaultService := &fakeCLIVaultService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
			"text-secret-id",
			"2",
			"updated note",
			"updated secret text",
		},
	}
	var stdout bytes.Buffer

	err := runCLI(context.Background(), []string{"update"}, authService, vaultService, prompter, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}

	if len(vaultService.updateSecretCalls) != 1 {
		t.Fatalf("UpdateSecret() calls = %d, want 1", len(vaultService.updateSecretCalls))
	}

	call := vaultService.updateSecretCalls[0]
	if call.input.ID != "text-secret-id" {
		t.Fatalf("secret id = %q, want text-secret-id", call.input.ID)
	}

	if call.input.ExpectedVersion != 2 {
		t.Fatalf("expected version = %d, want 2", call.input.ExpectedVersion)
	}

	if call.input.Type != core.SecretTypeText {
		t.Fatalf("secret type = %v, want text", call.input.Type)
	}

	if !strings.Contains(string(call.input.Metadata), "updated note") {
		t.Fatalf("metadata = %q, want updated title", call.input.Metadata)
	}

	if string(call.input.Payload) != "updated secret text" {
		t.Fatalf("payload = %q, want updated secret text", call.input.Payload)
	}

	wantHidden := []bool{false, true, true, false, false, false, true}
	if len(prompter.hidden) != len(wantHidden) {
		t.Fatalf("hidden prompts = %v, want %v", prompter.hidden, wantHidden)
	}

	for i := range wantHidden {
		if prompter.hidden[i] != wantHidden[i] {
			t.Fatalf("hidden prompt[%d] = %v, want %v", i, prompter.hidden[i], wantHidden[i])
		}
	}

	if !strings.Contains(stdout.String(), "3") {
		t.Fatalf("stdout = %q, want updated version", stdout.String())
	}
}

func TestDeleteTextSecretCommandPromptsVersionAndCallsVaultService(t *testing.T) {
	authService := &fakeCLIAuthService{}
	vaultService := &fakeCLIVaultService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
			"text-secret-id",
			"2",
		},
	}
	var stdout bytes.Buffer

	err := runCLI(context.Background(), []string{"delete"}, authService, vaultService, prompter, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}

	if len(vaultService.deleteSecretCalls) != 1 {
		t.Fatalf("DeleteSecret() calls = %d, want 1", len(vaultService.deleteSecretCalls))
	}

	call := vaultService.deleteSecretCalls[0]
	if call.input.ID != "text-secret-id" {
		t.Fatalf("secret id = %q, want text-secret-id", call.input.ID)
	}

	if call.input.ExpectedVersion != 2 {
		t.Fatalf("expected version = %d, want 2", call.input.ExpectedVersion)
	}

	if !strings.Contains(stdout.String(), "text-secret-id") {
		t.Fatalf("stdout = %q, want deleted secret id", stdout.String())
	}
}

func TestSyncCommandLogsInCallsVaultServiceAndPrintsSummary(t *testing.T) {
	authService := &fakeCLIAuthService{}
	vaultService := &fakeCLIVaultService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
		},
	}
	var stdout bytes.Buffer

	err := runCLI(context.Background(), []string{"sync"}, authService, vaultService, prompter, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}

	if len(authService.loginCalls) != 1 {
		t.Fatalf("Login() calls = %d, want 1", len(authService.loginCalls))
	}

	if len(vaultService.syncSecretsCalls) != 1 {
		t.Fatalf("SyncSecrets() calls = %d, want 1", len(vaultService.syncSecretsCalls))
	}

	if !vaultService.syncSecretsCalls[0].input.ChangedAfter.IsZero() {
		t.Fatalf("ChangedAfter = %s, want zero time for sync without offline cache", vaultService.syncSecretsCalls[0].input.ChangedAfter)
	}

	output := stdout.String()
	if !strings.Contains(output, "Синхронизация выполнена") {
		t.Fatalf("stdout = %q, want sync success message", output)
	}

	if !strings.Contains(output, "Получено изменений: 2") {
		t.Fatalf("stdout = %q, want changed count", output)
	}

	if !strings.Contains(output, "active-secret-id") {
		t.Fatalf("stdout = %q, want active secret id", output)
	}

	if !strings.Contains(output, "deleted-secret-id") {
		t.Fatalf("stdout = %q, want deleted secret id", output)
	}

	if !strings.Contains(output, "удален") {
		t.Fatalf("stdout = %q, want deleted marker", output)
	}
}

func TestUpdateTextSecretCommandReturnsClearConflictError(t *testing.T) {
	authService := &fakeCLIAuthService{}
	vaultService := &fakeCLIVaultService{
		updateSecretFunc: func(context.Context, core.Session, core.UpdateSecretInput) (core.Secret, error) {
			return core.Secret{}, errors.New("version conflict")
		},
	}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
			"text-secret-id",
			"2",
			"updated note",
			"updated secret text",
		},
	}

	err := runCLI(context.Background(), []string{"update"}, authService, vaultService, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("error = %q, want version conflict context", err.Error())
	}
}

func TestCreateTextSecretCommandReturnsClearErrorWhenLoginFails(t *testing.T) {
	authService := &fakeCLIAuthService{
		loginFunc: func(context.Context, core.LoginInput) (core.Session, error) {
			return core.Session{}, errors.New("invalid credentials")
		},
	}
	vaultService := &fakeCLIVaultService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"wrong-login-password",
			"master-password",
		},
	}

	err := runCLI(context.Background(), []string{"create"}, authService, vaultService, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "open vault") {
		t.Fatalf("error = %q, want open vault context", err.Error())
	}

	if len(vaultService.createSecretCalls) != 0 {
		t.Fatalf("CreateSecret() calls = %d, want 0", len(vaultService.createSecretCalls))
	}
}

func TestGetTextSecretCommandReturnsClearErrorWhenSecretIsMissing(t *testing.T) {
	authService := &fakeCLIAuthService{}
	vaultService := &fakeCLIVaultService{
		getSecretFunc: func(context.Context, core.Session, core.GetSecretInput) (core.Secret, error) {
			return core.Secret{}, errors.New("not found")
		},
	}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
			"missing-secret-id",
		},
	}

	err := runCLI(context.Background(), []string{"get"}, authService, vaultService, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "get text secret") {
		t.Fatalf("error = %q, want get text secret context", err.Error())
	}
}

func TestVaultCommandsRequireDependencies(t *testing.T) {
	prompter := &fakePrompter{}

	err := runCLI(context.Background(), []string{"create"}, nil, &fakeCLIVaultService{}, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI(create) error = nil, want error")
	}

	err = runCLI(context.Background(), []string{"get"}, &fakeCLIAuthService{}, nil, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI(get) error = nil, want error")
	}

	err = runCLI(context.Background(), []string{"list"}, &fakeCLIAuthService{}, nil, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI(list) error = nil, want error")
	}

	err = runCLI(context.Background(), []string{"update"}, &fakeCLIAuthService{}, nil, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI(update) error = nil, want error")
	}

	err = runCLI(context.Background(), []string{"delete"}, &fakeCLIAuthService{}, nil, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI(delete) error = nil, want error")
	}

	err = runCLI(context.Background(), []string{"sync"}, &fakeCLIAuthService{}, nil, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI(sync) error = nil, want error")
	}
}
