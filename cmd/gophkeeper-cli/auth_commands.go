package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
)

// CLIAuthService описывает auth flow, который нужен CLI-командам
type CLIAuthService interface {
	Register(context.Context, core.RegisterInput) (core.Session, error)
	Login(context.Context, core.LoginInput) (core.Session, error)
}

// Prompter получает пользовательский ввод для CLI
type Prompter interface {
	Prompt(label string) (string, error)
	PromptHidden(label string) (string, error)
}

func validateDifferentPasswords(loginPass string, masterPass string) error {
	if loginPass == masterPass {
		return fmt.Errorf("login password and master password must be different")
	}

	return nil
}

func runRegister(ctx context.Context, authService CLIAuthService, prompter Prompter, stdout io.Writer, stderr io.Writer) error {
	if authService == nil {
		return fmt.Errorf("auth service is required")
	}

	if prompter == nil {
		return fmt.Errorf("prompter is required")
	}

	login, err := prompter.Prompt("Login")
	if err != nil {
		return fmt.Errorf("read login: %w", err)
	}

	loginPassword, err := prompter.PromptHidden("Login password")
	if err != nil {
		return fmt.Errorf("read login password: %w", err)
	}

	fmt.Fprintln(stderr, "Внимание: мастер-пароль невозможно восстановить")

	masterPassword, err := prompter.PromptHidden("Master password")
	if err != nil {
		return fmt.Errorf("read master password: %w", err)
	}

	if err = validateDifferentPasswords(loginPassword, masterPassword); err != nil {
		return err
	}

	masterPasswordRepeat, err := prompter.PromptHidden("Repeat master password")
	if err != nil {
		return fmt.Errorf("repeat master password: %w", err)
	}

	if masterPassword != masterPasswordRepeat {
		return fmt.Errorf("master passwords do not match")
	}

	_, err = authService.Register(ctx, core.RegisterInput{
		Login:          strings.TrimSpace(login),
		LoginPassword:  loginPassword,
		MasterPassword: masterPassword,
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	fmt.Fprintln(stdout, "Регистрация выполнена")
	return nil
}

func runLogin(ctx context.Context, authService CLIAuthService, prompter Prompter, stdout io.Writer) error {
	if authService == nil {
		return fmt.Errorf("auth service is required")
	}

	if prompter == nil {
		return fmt.Errorf("prompter is required")
	}

	login, err := prompter.Prompt("Login")
	if err != nil {
		return fmt.Errorf("read login: %w", err)
	}

	loginPassword, err := prompter.PromptHidden("Login password")
	if err != nil {
		return fmt.Errorf("read login password: %w", err)
	}

	masterPassword, err := prompter.PromptHidden("Master password")
	if err != nil {
		return fmt.Errorf("read master password: %w", err)
	}

	if err = validateDifferentPasswords(loginPassword, masterPassword); err != nil {
		return err
	}

	_, err = authService.Login(ctx, core.LoginInput{
		Login:          strings.TrimSpace(login),
		LoginPassword:  loginPassword,
		MasterPassword: masterPassword,
	})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	fmt.Fprintln(stdout, "Вход выполнен")
	return nil
}

func runCLI(
	ctx context.Context,
	args []string,
	authService CLIAuthService,
	vaultService CLIVaultService,
	prompter Prompter,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if len(args) == 0 {
		printUsageTo(stdout)
		return nil
	}

	switch args[0] {
	case "register":
		return runRegister(ctx, authService, prompter, stdout, stderr)
	case "login":
		return runLogin(ctx, authService, prompter, stdout)
	case "create":
		return runCreateTextSecret(ctx, authService, vaultService, prompter, stdout)
	case "get":
		return runGetTextSecret(ctx, authService, vaultService, prompter, stdout)
	case "version":
		printVersionTo(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}
