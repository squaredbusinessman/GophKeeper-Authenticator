//go:build tools

// Package tools фиксирует CLI-инструменты разработки в go.mod
package tools

import (
	_ "github.com/pressly/goose/v3/cmd/goose"
)

/*сервер не импортирует goose;
CLI не импортирует goose;
production binary не тащит migration tool внутрь;
go mod tidy не удаляет зависимость;
команда разработки остается воспроизводимой.*/
