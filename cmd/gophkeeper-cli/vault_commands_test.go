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

	createSecretCalls []createSecretCall
	getSecretCalls    []getSecretCall
}

type createSecretCall struct {
	session core.Session
	input   core.CreateSecretInput
}

type getSecretCall struct {
	session core.Session
	input   core.GetSecretInput
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
}
