package main

import (
	"fmt"
	"os"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/shared/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "version":
		printVersion()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printVersion() {
	info := version.Get()

	fmt.Printf("GophKeeper CLI\n")
	fmt.Printf("Version: %s\n", info.Version)
	fmt.Printf("Build date: %s\n", info.BuildDate)
	fmt.Printf("Commit: %s\n", info.Commit)
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  gophkeeper version")
}
