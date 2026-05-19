package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"golang.org/x/term"
)

// terminalPrompter читает обычный и скрытый ввод из терминала
type terminalPrompter struct {
	stdin  io.Reader
	stdout io.Writer
	fd     int
}

// newTerminalPrompter создает prompter для интерактивного CLI
func newTerminalPrompter(stdin io.Reader, stdout io.Writer, fd int) *terminalPrompter {
	return &terminalPrompter{
		stdin:  stdin,
		stdout: stdout,
		fd:     fd,
	}
}

// Prompt читает обычное значение с отображением ввода
func (p *terminalPrompter) Prompt(label string) (string, error) {
	fmt.Fprintf(p.stdout, "%s: ", label)

	reader := bufio.NewReader(p.stdin)
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input prompt: %w", err)
	}

	return strings.TrimSpace(value), nil
}

// PromptHidden читает значение без отображения ввода в терминале
func (p *terminalPrompter) PromptHidden(label string) (string, error) {
	fmt.Fprintf(p.stdout, "%s: ", label)

	value, err := term.ReadPassword(p.fd)
	fmt.Fprintln(p.stdout)
	if err != nil {
		return "", fmt.Errorf("failed to read input hidden prompt: %w", err)
	}

	return string(value), nil
}
