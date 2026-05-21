package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/config"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
	gophkeeperv1 "github.com/squaredbusinessman/gophkeeper-authenticator/internal/gen/proto/gophkeeper/v1"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", userFacingError(err))
		os.Exit(1)
	}
}

func printVersion() {
	printVersionTo(os.Stdout)
}

func printVersionTo(stdout io.Writer) {
	info := version.Get()

	fmt.Fprintln(stdout, "GophKeeper CLI")
	fmt.Fprintf(stdout, "Version: %s\n", info.Version)
	fmt.Fprintf(stdout, "Build date: %s\n", info.BuildDate)
	fmt.Fprintf(stdout, "Commit: %s\n", info.Commit)
}

func printUsage() {
	printUsageTo(os.Stdout)
}

func printUsageTo(stdout io.Writer) {
	fmt.Fprintln(stdout, "Usage:")
	fmt.Fprintln(stdout, "  gophkeeper version")
	fmt.Fprintln(stdout, "  gophkeeper register")
	fmt.Fprintln(stdout, "  gophkeeper login")
	fmt.Fprintln(stdout, "  gophkeeper create [text|login-password|bank-card|binary]")
	fmt.Fprintln(stdout, "  gophkeeper get")
	fmt.Fprintln(stdout, "  gophkeeper list")
	fmt.Fprintln(stdout, "  gophkeeper update [text|login-password|bank-card|binary]")
	fmt.Fprintln(stdout, "  gophkeeper delete")
	fmt.Fprintln(stdout, "  gophkeeper sync")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Examples:")
	fmt.Fprintln(stdout, "  gophkeeper create text")
	fmt.Fprintln(stdout, "  gophkeeper create login-password")
	fmt.Fprintln(stdout, "  gophkeeper create bank-card")
	fmt.Fprintln(stdout, "  gophkeeper create binary")
	fmt.Fprintln(stdout, "  gophkeeper update text")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Notes:")
	fmt.Fprintln(stdout, "  delete работает для любого типа секрета")
	fmt.Fprintln(stdout, "  version для update/delete берите из get, list или sync")
}

func userFacingError(err error) string {
	if err == nil {
		return ""
	}

	message := err.Error()
	lowerMessage := strings.ToLower(message)

	switch {
	case strings.Contains(lowerMessage, "connection refused") ||
		strings.Contains(lowerMessage, "error while dialing") ||
		strings.Contains(lowerMessage, "code = unavailable"):
		return "не удалось подключиться к серверу. Проверьте, что gophkeeper-server запущен и адрес GOPHKEEPER_SERVER_ADDRESS указан верно"
	case strings.Contains(lowerMessage, "version conflict") ||
		strings.Contains(lowerMessage, "code = failedprecondition"):
		return "version conflict: версия секрета устарела. Выполните gophkeeper list или gophkeeper sync и повторите команду с актуальной version"
	case strings.Contains(lowerMessage, "could not decrypt vault key") ||
		strings.Contains(lowerMessage, "message authentication failed"):
		return "неверный мастер-пароль: vault key не удалось расшифровать"
	default:
		return message
	}
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "version" {
		return runCLI(ctx, args, nil, nil, nil, stdout, stderr)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	conn, err := grpc.NewClient(
		cfg.ServerAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("error creating grpc client: %w", err)
	}
	defer conn.Close()

	authClient := gophkeeperv1.NewAuthServiceClient(conn)
	vaultClient := gophkeeperv1.NewVaultServiceClient(conn)
	tokenStore := core.NewFileTokenStore(cfg.TokenFile)
	authService := core.NewAuthService(authClient, tokenStore)
	vaultService := core.NewVaultService(vaultClient)
	prompter := newTerminalPrompter(os.Stdin, stdout, int(os.Stdin.Fd()))

	return runCLI(ctx, args, authService, vaultService, prompter, stdout, stderr)
}
