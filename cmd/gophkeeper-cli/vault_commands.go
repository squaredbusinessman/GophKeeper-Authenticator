package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
)

// CLIVaultService описывает vault flow, который нужен CLI-командам
type CLIVaultService interface {
	CreateSecret(context.Context, core.Session, core.CreateSecretInput) (core.Secret, error)
	GetSecret(context.Context, core.Session, core.GetSecretInput) (core.Secret, error)
	ListSecrets(context.Context, core.Session, core.ListSecretsInput) ([]core.Secret, error)
	UpdateSecret(context.Context, core.Session, core.UpdateSecretInput) (core.Secret, error)
	DeleteSecret(context.Context, core.Session, core.DeleteSecretInput) (core.DeleteSecretResult, error)
	SyncSecrets(context.Context, core.Session, core.SyncSecretsInput) (core.SyncSecretsResult, error)
}

type secretKind string

const (
	secretKindText          secretKind = "text"
	secretKindLoginPassword secretKind = "login-password"
	secretKindBankCard      secretKind = "bank-card"
	secretKindBinary        secretKind = "binary"
)

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

	textPayload, schemaVersion, err := core.EncodeTextPayload(core.TextPayload{
		Text: secretText,
	})
	if err != nil {
		return fmt.Errorf("encode text payload: %w", err)
	}

	secret, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeText,
		Metadata:             metadata,
		Payload:              textPayload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		return fmt.Errorf("create text secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет создан: %s\n", secret.ID)
	return nil
}

func runCreateSecret(
	ctx context.Context,
	args []string,
	authService CLIAuthService,
	vaultService CLIVaultService,
	prompter Prompter,
	stdout io.Writer,
) error {
	kind := parseSecretKind(args)

	switch kind {
	case secretKindText:
		return runCreateTextSecret(ctx, authService, vaultService, prompter, stdout)
	case secretKindLoginPassword:
		return runCreateLoginPasswordSecret(ctx, authService, vaultService, prompter, stdout)
	case secretKindBankCard:
		return runCreateBankCardSecret(ctx, authService, vaultService, prompter, stdout)
	case secretKindBinary:
		return runCreateBinarySecret(ctx, authService, vaultService, prompter, stdout)

	default:
		return fmt.Errorf("unsupported secret type: %s", kind)
	}
}

func runCreateLoginPasswordSecret(
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

	title, err := promptRequired(prompter, "Title")
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	login, err := promptRequired(prompter, "Secret login")
	if err != nil {
		return fmt.Errorf("read secret login: %w", err)
	}

	password, err := prompter.PromptHidden("Secret password")
	if err != nil {
		return fmt.Errorf("read secret password: %w", err)
	}

	if password == "" {
		return fmt.Errorf("secret password is required")
	}

	url, err := prompter.Prompt("URL")
	if err != nil {
		return fmt.Errorf("read url: %w", err)
	}

	notes, err := prompter.Prompt("Notes")
	if err != nil {
		return fmt.Errorf("read notes: %w", err)
	}

	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return fmt.Errorf("encode login/password secret metadata: %w", err)
	}

	payload, schemaVersion, err := core.EncodeLoginPasswordPayload(core.LoginPasswordPayload{
		Login:    login,
		Password: password,
		URL:      strings.TrimSpace(url),
		Notes:    strings.TrimSpace(notes),
	})
	if err != nil {
		return fmt.Errorf("encode login/password payload: %w", err)
	}

	secret, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeLoginPassword,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		return fmt.Errorf("create login/password secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет создан: %s\n", secret.ID)
	return nil
}

func runCreateBankCardSecret(
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

	title, err := promptRequired(prompter, "Title")
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	cardNumber, err := promptRequired(prompter, "Card number")
	if err != nil {
		return fmt.Errorf("read card number: %w", err)
	}

	cardholderName, err := promptRequired(prompter, "Cardholder name")
	if err != nil {
		return fmt.Errorf("read cardholder name: %w", err)
	}

	expirationMonth, err := promptRequired(prompter, "Expiration month")
	if err != nil {
		return fmt.Errorf("read expiration month: %w", err)
	}

	expirationYear, err := promptRequired(prompter, "Expiration year")
	if err != nil {
		return fmt.Errorf("read expiration year: %w", err)
	}

	cvv, err := prompter.PromptHidden("CVV")
	if err != nil {
		return fmt.Errorf("read cvv: %w", err)
	}

	notes, err := prompter.Prompt("Notes")
	if err != nil {
		return fmt.Errorf("read notes: %w", err)
	}

	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return fmt.Errorf("encode bank card metadata: %w", err)
	}

	payload, schemaVersion, err := core.EncodeBankCardPayload(core.BankCardPayload{
		Number:          cardNumber,
		CardholderName:  cardholderName,
		ExpirationMonth: expirationMonth,
		ExpirationYear:  expirationYear,
		CVV:             cvv,
		Notes:           strings.TrimSpace(notes),
	})
	if err != nil {
		return fmt.Errorf("encode bank card payload: %w", err)
	}

	secret, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeBankCard,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		return fmt.Errorf("create bank card secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет создан: %s\n", secret.ID)
	return nil
}

func runCreateBinarySecret(
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

	title, err := promptRequired(prompter, "Title")
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	filePath, err := promptRequired(prompter, "File path")
	if err != nil {
		return fmt.Errorf("read file path: %w", err)
	}

	contentType, err := prompter.Prompt("Content type")
	if err != nil {
		return fmt.Errorf("read content type: %w", err)
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read binary file: %w", err)
	}

	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return fmt.Errorf("encode binary metadata: %w", err)
	}

	payload, schemaVersion, err := core.EncodeBinaryPayload(core.BinaryPayload{
		FileName:    filepath.Base(filePath),
		ContentType: strings.TrimSpace(contentType),
		Data:        fileData,
	})
	if err != nil {
		return fmt.Errorf("encode binary payload: %w", err)
	}

	secret, err := vaultService.CreateSecret(ctx, session, core.CreateSecretInput{
		Type:                 core.SecretTypeBinary,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		return fmt.Errorf("create binary secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет создан: %s\n", secret.ID)
	return nil
}

func runGetSecret(
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

	id, err := promptRequired(prompter, "Secret ID")
	if err != nil {
		return fmt.Errorf("read secret id: %w", err)
	}

	secret, err := vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: id})
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}

	return printSecret(stdout, prompter, secret)
}

func runListSecrets(ctx context.Context, authService CLIAuthService, vaultService CLIVaultService, prompter Prompter, stdout io.Writer) error {
	if vaultService == nil {
		return fmt.Errorf("vault service is required")
	}

	session, err := openVaultSession(ctx, authService, prompter)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	secrets, err := vaultService.ListSecrets(ctx, session, core.ListSecretsInput{})
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}

	for _, secret := range secrets {
		if secret.DeletedAt != nil {
			continue
		}

		title := decodeTextSecretTitle(secret.Metadata)
		if title == "" {
			title = "<без названия>"
		}

		fmt.Fprintf(stdout, "%s | version %d | %s | %s\n", secret.ID, secret.Version, secretTypeLabel(secret.Type), title)
	}

	return nil
}

func runUpdateSecret(
	ctx context.Context,
	args []string,
	authService CLIAuthService,
	vaultService CLIVaultService,
	prompter Prompter,
	stdout io.Writer,
) error {
	kind := parseSecretKind(args)

	switch kind {
	case secretKindText:
		return runUpdateTextSecret(ctx, authService, vaultService, prompter, stdout)
	case secretKindLoginPassword:
		return runUpdateLoginPasswordSecret(ctx, authService, vaultService, prompter, stdout)
	case secretKindBankCard:
		return runUpdateBankCardSecret(ctx, authService, vaultService, prompter, stdout)
	case secretKindBinary:
		return runUpdateBinarySecret(ctx, authService, vaultService, prompter, stdout)
	default:
		return fmt.Errorf("unsupported secret type: %s", kind)
	}
}

func runUpdateLoginPasswordSecret(ctx context.Context, authService CLIAuthService, vaultService CLIVaultService, prompter Prompter, stdout io.Writer) error {
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

	title, err := promptRequired(prompter, "Title")
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	login, err := promptRequired(prompter, "Secret login")
	if err != nil {
		return fmt.Errorf("read secret login: %w", err)
	}

	password, err := prompter.PromptHidden("Secret password")
	if err != nil {
		return fmt.Errorf("read secret password: %w", err)
	}

	if password == "" {
		return fmt.Errorf("secret password is required")
	}

	url, err := prompter.Prompt("URL")
	if err != nil {
		return fmt.Errorf("read url: %w", err)
	}

	notes, err := prompter.Prompt("Notes")
	if err != nil {
		return fmt.Errorf("read notes: %w", err)
	}

	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return fmt.Errorf("encode login/password secret metadata: %w", err)
	}

	payload, schemaVersion, err := core.EncodeLoginPasswordPayload(core.LoginPasswordPayload{
		Login:    login,
		Password: password,
		URL:      strings.TrimSpace(url),
		Notes:    strings.TrimSpace(notes),
	})
	if err != nil {
		return fmt.Errorf("encode login/password payload: %w", err)
	}

	secret, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   id,
		ExpectedVersion:      expectedVersion,
		Type:                 core.SecretTypeLoginPassword,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		return fmt.Errorf("version conflict: update login/password secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет обновлен: %s, version: %d\n", secret.ID, secret.Version)
	return nil
}

func runUpdateBankCardSecret(ctx context.Context, authService CLIAuthService, vaultService CLIVaultService, prompter Prompter, stdout io.Writer) error {
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

	title, err := promptRequired(prompter, "Title")
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	cardNumber, err := promptRequired(prompter, "Card number")
	if err != nil {
		return fmt.Errorf("read card number: %w", err)
	}

	cardholderName, err := promptRequired(prompter, "Cardholder name")
	if err != nil {
		return fmt.Errorf("read cardholder name: %w", err)
	}

	expirationMonth, err := promptRequired(prompter, "Expiration month")
	if err != nil {
		return fmt.Errorf("read expiration month: %w", err)
	}

	expirationYear, err := promptRequired(prompter, "Expiration year")
	if err != nil {
		return fmt.Errorf("read expiration year: %w", err)
	}

	cvv, err := prompter.PromptHidden("CVV")
	if err != nil {
		return fmt.Errorf("read cvv: %w", err)
	}

	notes, err := prompter.Prompt("Notes")
	if err != nil {
		return fmt.Errorf("read notes: %w", err)
	}

	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return fmt.Errorf("encode bank card metadata: %w", err)
	}

	payload, schemaVersion, err := core.EncodeBankCardPayload(core.BankCardPayload{
		Number:          cardNumber,
		CardholderName:  cardholderName,
		ExpirationMonth: expirationMonth,
		ExpirationYear:  expirationYear,
		CVV:             cvv,
		Notes:           strings.TrimSpace(notes),
	})
	if err != nil {
		return fmt.Errorf("encode bank card payload: %w", err)
	}

	secret, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   id,
		ExpectedVersion:      expectedVersion,
		Type:                 core.SecretTypeBankCard,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		return fmt.Errorf("version conflict: update bank card secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет обновлен: %s, version: %d\n", secret.ID, secret.Version)
	return nil
}

func runUpdateBinarySecret(ctx context.Context, authService CLIAuthService, vaultService CLIVaultService, prompter Prompter, stdout io.Writer) error {
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

	title, err := promptRequired(prompter, "Title")
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	filePath, err := promptRequired(prompter, "File path")
	if err != nil {
		return fmt.Errorf("read file path: %w", err)
	}

	contentType, err := prompter.Prompt("Content type")
	if err != nil {
		return fmt.Errorf("read content type: %w", err)
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read binary file: %w", err)
	}

	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return fmt.Errorf("encode binary metadata: %w", err)
	}

	payload, schemaVersion, err := core.EncodeBinaryPayload(core.BinaryPayload{
		FileName:    filepath.Base(filePath),
		ContentType: strings.TrimSpace(contentType),
		Data:        fileData,
	})
	if err != nil {
		return fmt.Errorf("encode binary payload: %w", err)
	}

	secret, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   id,
		ExpectedVersion:      expectedVersion,
		Type:                 core.SecretTypeBinary,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: schemaVersion,
	})
	if err != nil {
		return fmt.Errorf("version conflict: update binary secret: %w", err)
	}

	fmt.Fprintf(stdout, "Секрет обновлен: %s, version: %d\n", secret.ID, secret.Version)
	return nil
}

func runSyncSecrets(ctx context.Context, authService CLIAuthService, vaultService CLIVaultService, prompter Prompter, stdout io.Writer) error {
	if vaultService == nil {
		return fmt.Errorf("vault service is required")
	}

	session, err := openVaultSession(ctx, authService, prompter)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	result, err := vaultService.SyncSecrets(ctx, session, core.SyncSecretsInput{})
	if err != nil {
		return fmt.Errorf("sync secrets: %w", err)
	}

	fmt.Fprintln(stdout, "Синхронизация выполнена")
	fmt.Fprintf(stdout, "Получено изменений: %d\n", len(result.Secrets))

	for _, secret := range result.Secrets {
		title := decodeTextSecretTitle(secret.Metadata)
		if title == "" {
			title = "<без названия>"
		}

		status := "active"
		if secret.DeletedAt != nil {
			status = "удален"
		}

		fmt.Fprintf(stdout, "%s | version %d | %s | %s | %s\n", secret.ID, secret.Version, status, secretTypeLabel(secret.Type), title)
	}

	if !result.NextChangedAfter.IsZero() {
		fmt.Fprintf(stdout, "Next changed after: %s\n", result.NextChangedAfter.Format(time.RFC3339))
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

	textPayload, schemaVersion, err := core.EncodeTextPayload(core.TextPayload{
		Text: secretText,
	})
	if err != nil {
		return fmt.Errorf("encode text payload: %w", err)
	}

	secret, err := vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
		ID:                   id,
		ExpectedVersion:      expectedVersion,
		Type:                 core.SecretTypeText,
		Metadata:             metadata,
		Payload:              textPayload,
		PayloadSchemaVersion: schemaVersion,
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

func parseSecretKind(args []string) secretKind {
	if len(args) == 0 {
		return secretKindText
	}

	switch strings.TrimSpace(args[0]) {
	case "", "text":
		return secretKindText
	case "login-password", "login_password":
		return secretKindLoginPassword
	case "bank-card", "bank_card":
		return secretKindBankCard
	case "binary":
		return secretKindBinary
	default:
		return secretKind(args[0])
	}
}

func promptRequired(prompter Prompter, label string) (string, error) {
	value, err := prompter.Prompt(label)
	if err != nil {
		return "", err
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", strings.ToLower(label))
	}

	return value, nil
}

func printSecret(stdout io.Writer, prompter Prompter, secret core.Secret) error {
	title := decodeTextSecretTitle(secret.Metadata)
	if title != "" {
		fmt.Fprintf(stdout, "Title: %s\n", title)
	}

	switch secret.Type {
	case core.SecretTypeText:
		textPayload, err := core.DecodeTextPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return fmt.Errorf("decode text payload: %w", err)
		}

		fmt.Fprintf(stdout, "Type: %s\n", secretTypeLabel(secret.Type))
		fmt.Fprintf(stdout, "Secret text: %s\n", textPayload.Text)
		return nil

	case core.SecretTypeLoginPassword:
		loginPasswordPayload, err := core.DecodeLoginPasswordPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return fmt.Errorf("decode login/password payload: %w", err)
		}

		fmt.Fprintf(stdout, "Type: %s\n", secretTypeLabel(secret.Type))
		fmt.Fprintf(stdout, "Login: %s\n", loginPasswordPayload.Login)
		fmt.Fprintf(stdout, "Password: %s\n", loginPasswordPayload.Password)

		if loginPasswordPayload.URL != "" {
			fmt.Fprintf(stdout, "URL: %s\n", loginPasswordPayload.URL)
		}

		if loginPasswordPayload.Notes != "" {
			fmt.Fprintf(stdout, "Notes: %s\n", loginPasswordPayload.Notes)
		}

		return nil

	case core.SecretTypeBankCard:
		bankCardPayload, err := core.DecodeBankCardPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return fmt.Errorf("decode bank card payload: %w", err)
		}

		fmt.Fprintf(stdout, "Type: %s\n", secretTypeLabel(secret.Type))
		fmt.Fprintf(stdout, "Card number: %s\n", bankCardPayload.Number)
		fmt.Fprintf(stdout, "Cardholder name: %s\n", bankCardPayload.CardholderName)
		fmt.Fprintf(stdout, "Expiration: %s/%s\n", bankCardPayload.ExpirationMonth, bankCardPayload.ExpirationYear)

		if bankCardPayload.CVV != "" {
			fmt.Fprintf(stdout, "CVV: %s\n", bankCardPayload.CVV)
		}

		if bankCardPayload.Notes != "" {
			fmt.Fprintf(stdout, "Notes: %s\n", bankCardPayload.Notes)
		}

		return nil
	case core.SecretTypeBinary:
		binaryPayload, err := core.DecodeBinaryPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return fmt.Errorf("decode binary payload: %w", err)
		}

		outputPath, err := promptRequired(prompter, "Output path")
		if err != nil {
			return fmt.Errorf("read output path: %w", err)
		}

		if err = os.WriteFile(outputPath, binaryPayload.Data, 0o600); err != nil {
			return fmt.Errorf("write binary file: %w", err)
		}

		fmt.Fprintf(stdout, "Type: %s\n", secretTypeLabel(secret.Type))
		fmt.Fprintf(stdout, "File name: %s\n", binaryPayload.FileName)
		fmt.Fprintf(stdout, "Content type: %s\n", binaryPayload.ContentType)
		fmt.Fprintf(stdout, "Size bytes: %d\n", binaryPayload.SizeBytes)
		fmt.Fprintf(stdout, "Checksum SHA256: %s\n", binaryPayload.ChecksumSHA256)
		fmt.Fprintf(stdout, "Written to: %s\n", outputPath)
		return nil
	default:
		return fmt.Errorf("unsupported secret type: %s", secretTypeLabel(secret.Type))
	}
}

func secretTypeLabel(secretType core.SecretType) string {
	switch secretType {
	case core.SecretTypeText:
		return "text"
	case core.SecretTypeLoginPassword:
		return "login_password"
	case core.SecretTypeBankCard:
		return "bank_card"
	case core.SecretTypeBinary:
		return "binary"
	default:
		return "unknown"
	}
}
