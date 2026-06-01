package app

import (
	"fmt"
	"strings"

	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
)

// SessionState хранит открытую клиентскую сессию для UI-слоя
type SessionState struct {
	session core.Session
	open    bool
}

// NewSessionState создает пустое состояние сессии
func NewSessionState() *SessionState {
	return &SessionState{}
}

// SetSession сохраняет открытую vault-сессию
func (s *SessionState) SetSession(session core.Session) error {
	if s == nil {
		return fmt.Errorf("session state is required")
	}

	if strings.TrimSpace(session.AccessToken) == "" {
		return fmt.Errorf("access token is required")
	}

	if len(session.VaultKey) == 0 {
		return fmt.Errorf("vault key is required")
	}

	s.session = session
	s.open = true
	return nil
}

// Session возвращает текущую сессию и признак открытого vault
func (s *SessionState) Session() (core.Session, bool) {
	if s == nil || !s.open {
		return core.Session{}, false
	}

	return s.session, true
}

// Clear сбрасывает открытую сессию
func (s *SessionState) Clear() {
	if s == nil {
		return
	}

	s.session = core.Session{}
	s.open = false
}
