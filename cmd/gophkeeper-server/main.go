package main

import (
	"context"
	"os"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/server/app"
)

func main() {
	if err := app.Run(context.Background()); err != nil {
		os.Exit(1)
	}
}
