package main

import (
	"context"
	"fmt"
	"os"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/app"
)

func main() {
	if err := app.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
