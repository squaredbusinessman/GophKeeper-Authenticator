package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	clientapp "github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/app"
)

func main() {
	runtime, err := clientapp.LoadRuntime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", clientapp.UserFacingError(err))
		os.Exit(1)
	}
	defer runtime.Close()

	deps := appDeps{
		authService:  runtime.AuthService,
		vaultService: runtime.VaultService,
		blobService:  runtime.BlobService,
		sessionState: clientapp.NewSessionState(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	program := tea.NewProgram(newProgramModel(ctx, deps), tea.WithAltScreen(), tea.WithContext(ctx))
	if _, err = program.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", clientapp.UserFacingError(err))
		os.Exit(1)
	}
}
