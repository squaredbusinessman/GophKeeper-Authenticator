package main

import (
	"context"
	"fmt"
	"io"
	"os"

	clientapp "github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/app"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version"
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
	return clientapp.UserFacingError(err)
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "version" {
		return runCLI(ctx, args, nil, nil, nil, stdout, stderr)
	}

	runtime, err := clientapp.LoadRuntime()
	if err != nil {
		return err
	}
	defer runtime.Close()

	prompter := newTerminalPrompter(os.Stdin, stdout, int(os.Stdin.Fd()))

	return runCLI(ctx, args, runtime.AuthService, runtime.VaultService, prompter, stdout, stderr)
}
