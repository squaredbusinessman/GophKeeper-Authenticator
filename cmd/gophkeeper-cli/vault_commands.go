package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
)

// CLIVaultService описывает vault flow, который нужен CLI-командам
type CLIVaultService interface {
	CreateSecret(context.Context, core.Session, core.CreateSecretInput) (core.Secret, error)
	GetSecret(context.Context, core.Session, core.GetSecretInput) (core.Secret, error)
	ListSecrets(context.Context, core.Session, core.ListSecretsInput) ([]core.Secret, error)
	UpdateSecret(context.Context, core.Session, core.UpdateSecretInput) (core.Secret, error)
	DeleteSecret(context.Context, core.Session, core.DeleteSecretInput) (core.DeleteSecretResult, error)
}

type textSecretMetadata struct {
	Title string `json:"title"`
}

func runCreateTextSecret(
	ctx context.Context,
	authService CLIAuthService,
	vaultService CLIVaultService,
	prompter Prompter,
	stdout io.Writer,
) error {
	if vaultService == nil {
		return fmt.Errorf("vault service is required")
	}

	session, err := openVaultSession(ctx, authService, prompter)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	title, err := prompter.Prompt("Title")
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	title = strings.TrimSpace(title)
	if title == "" {
		return fmt.Errorf("title is required")
	}

	secretText, err := prompter.PromptHidden("Secret text")
	if err != nil {
		return fmt.Errorf("read secret text: %w", err)
	}

	if secretText == "" {
		return fmt.Errorf("secret text is required")
	}

	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return fmt.Errorf("encode text secret metadata: %w", err)
	}

	secret, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeText,
		Metadata:             metadata,
		Payload:              []byte(secretText),
		PayloadSchemaVersion: 1,
	})
	if err != nil {
		return fmt.Errorf("create text secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет создан: %s\n", secret.ID)
	return nil
}

func runGetTextSecret(
	ctx context.Context,
	authService CLIAuthService,
	vaultService CLIVaultService,
	prompter Prompter,
	stdout io.Writer,
) error {
	if vaultService == nil {
		return fmt.Errorf("vault service is required")
	}

	session, err := openVaultSession(ctx, authService, prompter)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	id, err := prompter.Prompt("Secret ID")
	if err != nil {
		return fmt.Errorf("read secret id: %w", err)
	}

	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("secret id is required")
	}

	secret, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: id})
	if err != nil {
		return fmt.Errorf("get text secret: %w", err)
	}

	if secret.Type != core.SecretTypeText {
		return fmt.Errorf("secret type is not text")
	}

	title := decodeTextSecretTitle(secret.Metadata)

	if title != "" {
		fmt.Fprintf(stdout, "Title: %s\n", title)
	}

	fmt.Fprintf(stdout, "Secret text: %s\n", string(secret.Payload))
	return nil
}

func runListTextSecrets(ctx context.Context, authService CLIAuthService, vaultService CLIVaultService, prompter Prompter, stdout io.Writer) error {
	if vaultService == nil {
		return fmt.Errorf("vault service is required")
	}

	session, err := openVaultSession(ctx, authService, prompter)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	secrets, err := vaultService.ListSecrets(ctx, session, core.ListSecretsInput{})
	if err != nil {
		return fmt.Errorf("list text secrets: %w", err)
	}

	for _, secret := range secrets {
		if secret.DeletedAt != nil {
			continue
		}

		if secret.Type != core.SecretTypeText {
			continue
		}

		title := decodeTextSecretTitle(secret.Metadata)
		if title == "" {
			title = "<без названия>"
		}

		fmt.Fprintf(stdout, "%s | version %d | %s\n", secret.ID, secret.Version, title)
	}

	return nil
}

func runUpdateTextSecret(ctx context.Context, authService CLIAuthService, vaultService CLIVaultService, prompter Prompter, stdout io.Writer) error {
	if vaultService == nil {
		return fmt.Errorf("vault service is required")
	}

	session, err := openVaultSession(ctx, authService, prompter)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	id, expectedVersion, err := promptSecretIDAndVersion(prompter)
	if err != nil {
		return err
	}

	title, err := prompter.Prompt("Title")
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	title = strings.TrimSpace(title)
	if title == "" {
		return fmt.Errorf("title is required")
	}

	secretText, err := prompter.PromptHidden("Secret text")
	if err != nil {
		return fmt.Errorf("read secret text: %w", err)
	}

	if secretText == "" {
		return fmt.Errorf("secret text is required")
	}

	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return fmt.Errorf("encode text secret metadata: %w", err)
	}

	secret, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   id,
		ExpectedVersion:      expectedVersion,
		Type:                 core.SecretTypeText,
		Metadata:             metadata,
		Payload:              []byte(secretText),
		PayloadSchemaVersion: 1,
	})
	if err != nil {
		return fmt.Errorf("version conflict: update text secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет обновлен: %s, version: %d\n", secret.ID, secret.Version)
	return nil
}

func runDeleteTextSecret(ctx context.Context, authService CLIAuthService, vaultService CLIVaultService, prompter Prompter, stdout io.Writer) error {
	if vaultService == nil {
		return fmt.Errorf("vault service is required")
	}

	session, err := openVaultSession(ctx, authService, prompter)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	id, expectedVersion, err := promptSecretIDAndVersion(prompter)
	if err != nil {
		return err
	}

	result, err := vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
		ID:              id,
		ExpectedVersion: expectedVersion,
	})
	if err != nil {
		return fmt.Errorf("version conflict: delete text secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет удален: %s, version: %d\n", result.ID, result.Version)
	return nil
}

func openVaultSession(ctx context.Context, authService CLIAuthService, prompter Prompter) (core.Session, error) {
	if authService == nil {
		return core.Session{}, fmt.Errorf("auth service is required")
	}

	if prompter == nil {
		return core.Session{}, fmt.Errorf("prompter is required")
	}

	login, err := prompter.Prompt("Login")
	if err != nil {
		return core.Session{}, fmt.Errorf("read login: %w", err)
	}

	loginPassword, err := prompter.PromptHidden("Login password")
	if err != nil {
		return core.Session{}, fmt.Errorf("read login password: %w", err)
	}

	masterPassword, err := prompter.PromptHidden("Master password")
	if err != nil {
		return core.Session{}, fmt.Errorf("read master password: %w", err)
	}

	if err = validateDifferentPasswords(loginPassword, masterPassword); err != nil {
		return core.Session{}, err
	}

	session, err := authService.Login(ctx, core.LoginInput{
		Login:          strings.TrimSpace(login),
		LoginPassword:  loginPassword,
		MasterPassword: masterPassword,
	})
	if err != nil {
		return core.Session{}, fmt.Errorf("login: %w", err)
	}

	return session, nil
}

func encodeTextSecretMetadata(title string) ([]byte, error) {
	// json.Marshal, а не ручная сборка строки.
	// Так title с кавычками, переносами или спецсимволами не сломает metadata
	return json.Marshal(&textSecretMetadata{
		Title: title,
	})
}

func decodeTextSecretTitle(metadata []byte) string {
	var value textSecretMetadata
	if err := json.Unmarshal(metadata, &value); err != nil {
		return ""
	}

	return value.Title
}

func promptSecretIDAndVersion(prompter Prompter) (string, int64, error) {
	id, err := prompter.Prompt("Secret ID")
	if err != nil {
		return "", 0, fmt.Errorf("read secret id: %w", err)
	}

	id = strings.TrimSpace(id)
	if id == "" {
		return "", 0, fmt.Errorf("secret id is required")
	}

	rawVersion, err := prompter.Prompt("Expected version")
	if err != nil {
		return "", 0, fmt.Errorf("read expected version: %w", err)
	}

	expectedVersion, err := strconv.ParseInt(strings.TrimSpace(rawVersion), 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("expected version must be integer: %w", err)
	}

	if expectedVersion <= 0 {
		return "", 0, fmt.Errorf("expected version is required")
	}

	return id, expectedVersion, nil
}
