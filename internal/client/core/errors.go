package core

import "errors"

// ErrInvalidMasterPassword означает ошибку расшифровки vault key мастер-паролем
var ErrInvalidMasterPassword = errors.New("invalid master password")
