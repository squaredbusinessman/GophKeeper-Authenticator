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

type fakeCLIAuthService struct {
	registerFunc func(context.Context, core.RegisterInput) (core.Session, error)
	loginFunc    func(context.Context, core.LoginInput) (core.Session, error)

	registerCalls []core.RegisterInput
	loginCalls    []core.LoginInput
}

func (s *fakeCLIAuthService) Register(ctx context.Context, input core.RegisterInput) (core.Session, error) {
	s.registerCalls = append(s.registerCalls, input)
	if s.registerFunc != nil {
		return s.registerFunc(ctx, input)
	}

	return core.Session{
		AccessToken:          "access-token",
		AccessTokenExpiresAt: time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC),
		VaultKey:             bytes.Repeat([]byte{1}, 32),
	}, nil
}

func (s *fakeCLIAuthService) Login(ctx context.Context, input core.LoginInput) (core.Session, error) {
	s.loginCalls = append(s.loginCalls, input)
	if s.loginFunc != nil {
		return s.loginFunc(ctx, input)
	}

	return core.Session{
		AccessToken:          "access-token",
		AccessTokenExpiresAt: time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC),
		VaultKey:             bytes.Repeat([]byte{1}, 32),
	}, nil
}

type fakePrompter struct {
	values []string
	labels []string
	hidden []bool
}

func (p *fakePrompter) Prompt(label string) (string, error) {
	return p.next(label, false)
}

func (p *fakePrompter) PromptHidden(label string) (string, error) {
	return p.next(label, true)
}

func (p *fakePrompter) next(label string, hidden bool) (string, error) {
	p.labels = append(p.labels, label)
	p.hidden = append(p.hidden, hidden)

	if len(p.values) == 0 {
		return "", errors.New("prompt value missing")
	}

	value := p.values[0]
	p.values = p.values[1:]

	return value, nil
}

func TestRegisterCommandPromptsPasswordsHiddenAndCallsAuthService(t *testing.T) {
	authService := &fakeCLIAuthService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
			"master-password",
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runCLI(context.Background(), []string{"register"}, authService, prompter, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}

	if len(authService.registerCalls) != 1 {
		t.Fatalf("Register() calls = %d, want 1", len(authService.registerCalls))
	}

	input := authService.registerCalls[0]
	if input.Login != "user@example.com" {
		t.Fatalf("Login = %q, want user@example.com", input.Login)
	}

	if input.LoginPassword != "login-password" {
		t.Fatalf("LoginPassword = %q, want login-password", input.LoginPassword)
	}

	if input.MasterPassword != "master-password" {
		t.Fatalf("MasterPassword = %q, want master-password", input.MasterPassword)
	}

	wantHidden := []bool{false, true, true, true}
	if len(prompter.hidden) != len(wantHidden) {
		t.Fatalf("hidden prompts = %v, want %v", prompter.hidden, wantHidden)
	}

	for i := range wantHidden {
		if prompter.hidden[i] != wantHidden[i] {
			t.Fatalf("hidden prompt[%d] = %v, want %v", i, prompter.hidden[i], wantHidden[i])
		}
	}

	if !strings.Contains(stderr.String(), "мастер-пароль невозможно восстановить") {
		t.Fatalf("stderr = %q, want recovery warning", stderr.String())
	}

	if !strings.Contains(stdout.String(), "Регистрация выполнена") {
		t.Fatalf("stdout = %q, want success message", stdout.String())
	}
}

func TestRegisterCommandRejectsDifferentMasterPasswordRepeat(t *testing.T) {
	authService := &fakeCLIAuthService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
			"another-master-password",
		},
	}

	err := runCLI(context.Background(), []string{"register"}, authService, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI() error = nil, want error")
	}

	if len(authService.registerCalls) != 0 {
		t.Fatalf("Register() calls = %d, want 0", len(authService.registerCalls))
	}

}

func TestRegisterCommandRejectsEqualLoginAndMasterPasswords(t *testing.T) {
	authService := &fakeCLIAuthService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"same-password",
			"same-password",
			"same-password",
		},
	}

	err := runCLI(context.Background(), []string{"register"}, authService, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI() error = nil, want error")
	}

	if len(authService.registerCalls) != 0 {
		t.Fatalf("Register() calls = %d, want 0", len(authService.registerCalls))
	}

	if len(prompter.hidden) != 3 {
		t.Fatalf("hidden prompts = %d, want 3 without master password repeat", len(prompter.hidden))
	}
}

func TestLoginCommandPromptsPasswordsHiddenAndCallsAuthService(t *testing.T) {
	authService := &fakeCLIAuthService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"login-password",
			"master-password",
		},
	}
	var stdout bytes.Buffer

	err := runCLI(context.Background(), []string{"login"}, authService, prompter, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}

	if len(authService.loginCalls) != 1 {
		t.Fatalf("Login() calls = %d, want 1", len(authService.loginCalls))
	}

	input := authService.loginCalls[0]
	if input.Login != "user@example.com" {
		t.Fatalf("Login = %q, want user@example.com", input.Login)
	}

	if input.LoginPassword != "login-password" {
		t.Fatalf("LoginPassword = %q, want login-password", input.LoginPassword)
	}

	if input.MasterPassword != "master-password" {
		t.Fatalf("MasterPassword = %q, want master-password", input.MasterPassword)
	}

	wantHidden := []bool{false, true, true}
	for i := range wantHidden {
		if prompter.hidden[i] != wantHidden[i] {
			t.Fatalf("hidden prompt[%d] = %v, want %v", i, prompter.hidden[i], wantHidden[i])
		}
	}

	if !strings.Contains(stdout.String(), "Вход выполнен") {
		t.Fatalf("stdout = %q, want success message", stdout.String())
	}
}

func TestLoginCommandRejectsEqualLoginAndMasterPasswords(t *testing.T) {
	authService := &fakeCLIAuthService{}
	prompter := &fakePrompter{
		values: []string{
			"user@example.com",
			"same-password",
			"same-password",
		},
	}

	err := runCLI(context.Background(), []string{"login"}, authService, prompter, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("runCLI() error = nil, want error")
	}

	if len(authService.loginCalls) != 0 {
		t.Fatalf("Login() calls = %d, want 0", len(authService.loginCalls))
	}
}

func TestRunVersionDoesNotRequireClientDependencies(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(context.Background(), []string{"version"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}

	if !strings.Contains(stdout.String(), "GophKeeper CLI") {
		t.Fatalf("stdout = %q, want version output", stdout.String())
	}

	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty stderr", stderr.String())
	}
}
