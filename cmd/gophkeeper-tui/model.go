package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	clientapp "github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/app"
	"github.com/squaredbusinessman/gophkeeper-authenticator/internal/client/core"
)

type authService interface {
	Register(context.Context, core.RegisterInput) (core.Session, error)
	Login(context.Context, core.LoginInput) (core.Session, error)
}

type vaultService interface {
	CreateSecret(context.Context, core.Session, core.CreateSecretInput) (core.Secret, error)
	GetSecret(context.Context, core.Session, core.GetSecretInput) (core.Secret, error)
	ListSecrets(context.Context, core.Session, core.ListSecretsInput) ([]core.Secret, error)
	UpdateSecret(context.Context, core.Session, core.UpdateSecretInput) (core.Secret, error)
	DeleteSecret(context.Context, core.Session, core.DeleteSecretInput) (core.DeleteSecretResult, error)
	SyncSecrets(context.Context, core.Session, core.SyncSecretsInput) (core.SyncSecretsResult, error)
}

type blobService interface {
	UploadBinary(context.Context, core.Session, core.UploadBinaryInput) (core.BinaryPayload, error)
	DownloadBinary(context.Context, core.Session, core.DownloadBinaryInput) ([]byte, error)
}

type sessionState interface {
	SetSession(core.Session) error
	Session() (core.Session, bool)
	Clear()
}

type appDeps struct {
	authService  authService
	vaultService vaultService
	blobService  blobService
	sessionState sessionState
}

type screen int

const (
	screenWelcome screen = iota
	screenAuth
	screenList
	screenDetail
	screenTypeSelect
	screenForm
	screenDelete
	screenSaveBinary
)

type authMode int

const (
	authModeLogin authMode = iota
	authModeRegister
)

type formMode int

const (
	formModeCreate formMode = iota
	formModeUpdate
)

type secretKind string

const (
	secretKindText          secretKind = "text"
	secretKindLoginPassword secretKind = "login-password"
	secretKindBankCard      secretKind = "bank-card"
	secretKindBinary        secretKind = "binary"
	secretKindOTP           secretKind = "otp"
)

const banner = `
  ____  ___  ____  _   _ _  _______ _____ ____  _____ ____  
 / ___|/ _ \|  _ \| | | | |/ / ____| ____|  _ \| ____|  _ \ 
| |  _| | | | |_) | |_| | ' /|  _| |  _| | |_) |  _| | |_) |
| |_| | |_| |  __/|  _  | . \| |___| |___|  __/| |___|  _ < 
 \____|\___/|_|   |_| |_|_|\_\_____|_____|_|   |_____|_| \_\

 ____  _____ ____ ____  _____ _____ 
/ ___|| ____/ ___|  _ \| ____|_   _|
\___ \|  _|| |   | |_) |  _|   | |  
 ___) | |__| |___|  _ <| |___  | |  
|____/|_____\____|_| \_\_____| |_|  
`

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	mutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	activeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
)

type model struct {
	deps    appDeps
	screen  screen
	width   int
	height  int
	busy    bool
	status  string
	isError bool

	authMode authMode
	inputs   []textinput.Model
	focus    int

	secrets  []core.Secret
	selected int
	current  *core.Secret
	detail   viewport.Model

	formKind secretKind
	formMode formMode
	editID   string
	editVer  int64
}

type authDoneMsg struct {
	session core.Session
	err     error
}

type listDoneMsg struct {
	secrets []core.Secret
	err     error
}

type secretDoneMsg struct {
	secret core.Secret
	err    error
}

type deleteDoneMsg struct {
	err error
}

type syncDoneMsg struct {
	count int
	err   error
}

type saveDoneMsg struct {
	path string
	err  error
}

type otpTickMsg time.Time

type programModel struct {
	inner    model
	updateFn func(model, tea.Msg) (model, tea.Cmd)
}

func newProgramModel(ctx context.Context, deps appDeps) programModel {
	return programModel{
		inner: newModel(deps),
		updateFn: func(m model, msg tea.Msg) (model, tea.Cmd) {
			return m.update(ctx, msg)
		},
	}
}

func (m programModel) Init() tea.Cmd {
	return m.inner.init()
}

func (m programModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	inner, cmd := m.updateFn(m.inner, msg)
	m.inner = inner
	return m, cmd
}

func (m programModel) View() string {
	return m.inner.View()
}

func newModel(deps appDeps) model {
	m := model{
		deps:   deps,
		screen: screenWelcome,
		detail: viewport.New(80, 20),
	}
	m.setAuthInputs()
	return m
}

func (m model) init() tea.Cmd {
	return textinput.Blink
}

func (m model) update(ctx context.Context, msg tea.Msg) (model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.detail.Width = max(40, msg.Width-4)
		m.detail.Height = max(8, msg.Height-8)
		return m, nil
	case authDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		if err := m.deps.sessionState.SetSession(msg.session); err != nil {
			m.setError(err)
			return m, nil
		}
		m.statusOK("vault открыт")
		m.screen = screenList
		m.busy = true
		return m, m.loadSecretsCmd(ctx, false)
	case listDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.secrets = msg.secrets
		if m.selected >= len(m.secrets) {
			m.selected = max(0, len(m.secrets)-1)
		}
		m.statusOK(fmt.Sprintf("загружено секретов: %d", len(m.secrets)))
		return m, nil
	case secretDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.current = &msg.secret
		m.detail.SetContent(m.renderSecretDetail(msg.secret))
		m.screen = screenDetail
		m.statusOK("секрет загружен")
		if m.formMode == formModeCreate || m.formMode == formModeUpdate {
			m.busy = true
			if msg.secret.Type == core.SecretTypeOTP {
				return m, tea.Batch(m.loadSecretsCmd(ctx, false), otpTickCmd())
			}
			return m, m.loadSecretsCmd(ctx, false)
		}
		if msg.secret.Type == core.SecretTypeOTP {
			return m, otpTickCmd()
		}
		return m, nil
	case deleteDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.current = nil
		m.screen = screenList
		m.statusOK("секрет удален")
		m.busy = true
		return m, m.loadSecretsCmd(ctx, false)
	case syncDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.statusOK(fmt.Sprintf("синхронизация выполнена, изменений: %d", msg.count))
		m.busy = true
		return m, m.loadSecretsCmd(ctx, false)
	case saveDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.statusOK("binary сохранен: " + msg.path)
		m.screen = screenDetail
		return m, nil
	case otpTickMsg:
		if m.screen == screenDetail && m.current != nil && m.current.Type == core.SecretTypeOTP {
			m.detail.SetContent(m.renderSecretDetail(*m.current))
			return m, otpTickCmd()
		}
		return m, nil
	}

	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	if key.String() == "ctrl+c" {
		return m, tea.Quit
	}
	if m.busy {
		return m, nil
	}

	switch m.screen {
	case screenWelcome:
		return m.updateWelcome(key)
	case screenAuth:
		return m.updateAuth(ctx, key)
	case screenList:
		return m.updateList(ctx, key)
	case screenDetail:
		return m.updateDetail(ctx, key)
	case screenTypeSelect:
		return m.updateTypeSelect(key)
	case screenForm:
		return m.updateForm(ctx, key)
	case screenDelete:
		return m.updateDelete(ctx, key)
	case screenSaveBinary:
		return m.updateSaveBinary(ctx, key)
	default:
		return m, nil
	}
}

func (m model) View() string {
	body := ""
	switch m.screen {
	case screenWelcome:
		body = m.viewWelcome()
	case screenAuth:
		body = m.viewAuth()
	case screenList:
		body = m.viewList()
	case screenDetail:
		body = m.viewDetail()
	case screenTypeSelect:
		body = m.viewTypeSelect()
	case screenForm:
		body = m.viewForm()
	case screenDelete:
		body = m.viewDelete()
	case screenSaveBinary:
		body = m.viewSaveBinary()
	}

	return lipgloss.JoinVertical(lipgloss.Left, body, m.viewStatus())
}

func (m *model) setAuthInputs() {
	labels := []string{"Логин", "Пароль входа", "Мастер-пароль"}
	if m.authMode == authModeRegister {
		labels = append(labels, "Повтор мастер-пароля")
	}
	m.inputs = makeInputs(labels, map[int]bool{1: true, 2: true, 3: true})
	m.focus = 0
	m.inputs[0].Focus()
}

func (m model) updateWelcome(key tea.KeyMsg) (model, tea.Cmd) {
	switch key.String() {
	case "enter":
		m.screen = screenAuth
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateAuth(ctx context.Context, key tea.KeyMsg) (model, tea.Cmd) {
	switch key.String() {
	case "ctrl+r":
		m.authMode = authModeRegister
		m.setAuthInputs()
		return m, nil
	case "ctrl+l":
		m.authMode = authModeLogin
		m.setAuthInputs()
		return m, nil
	case "tab", "down":
		m.focusNext()
		return m, nil
	case "shift+tab", "up":
		m.focusPrev()
		return m, nil
	case "enter":
		if m.focus < len(m.inputs)-1 {
			m.focusNext()
			return m, nil
		}
		m.busy = true
		return m, m.submitAuthCmd(ctx)
	}
	return m.updateFocusedInput(key)
}

func (m model) updateList(ctx context.Context, key tea.KeyMsg) (model, tea.Cmd) {
	switch key.String() {
	case "q":
		m.resetToWelcome()
		return m, nil
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
	case "down", "j":
		if m.selected < len(m.secrets)-1 {
			m.selected++
		}
	case "r":
		m.busy = true
		return m, m.loadSecretsCmd(ctx, false)
	case "s":
		m.busy = true
		return m, m.syncCmd(ctx)
	case "n":
		m.screen = screenTypeSelect
	case "enter":
		if len(m.secrets) > 0 {
			m.busy = true
			return m, m.getSecretCmd(ctx, m.secrets[m.selected].ID)
		}
	case "u":
		if len(m.secrets) > 0 {
			return m.startUpdateForm(m.secrets[m.selected])
		}
	case "d":
		if len(m.secrets) > 0 {
			secret := m.secrets[m.selected]
			m.current = &secret
			m.screen = screenDelete
		}
	}
	return m, nil
}

func (m model) updateDetail(_ context.Context, key tea.KeyMsg) (model, tea.Cmd) {
	var cmd tea.Cmd
	m.detail, cmd = m.detail.Update(key)

	switch key.String() {
	case "esc", "backspace":
		m.screen = screenList
		return m, nil
	case "u":
		if m.current != nil {
			return m.startUpdateForm(*m.current)
		}
	case "d":
		if m.current != nil {
			m.screen = screenDelete
		}
	case "s":
		if m.current != nil && m.current.Type == core.SecretTypeBinary {
			m.inputs = makeInputs([]string{"Папка для сохранения"}, nil)
			m.focus = 0
			m.inputs[0].Focus()
			m.screen = screenSaveBinary
		}
	}

	if m.current != nil && m.current.Type == core.SecretTypeOTP {
		m.detail.SetContent(m.renderSecretDetail(*m.current))
	}
	return m, cmd
}

func (m model) updateTypeSelect(key tea.KeyMsg) (model, tea.Cmd) {
	switch key.String() {
	case "esc", "backspace":
		m.screen = screenList
	case "t":
		return m.startCreateForm(secretKindText)
	case "p":
		return m.startCreateForm(secretKindLoginPassword)
	case "c":
		return m.startCreateForm(secretKindBankCard)
	case "b":
		return m.startCreateForm(secretKindBinary)
	case "o":
		return m.startCreateForm(secretKindOTP)
	}
	return m, nil
}

func (m model) updateForm(ctx context.Context, key tea.KeyMsg) (model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.screen = screenList
		return m, nil
	case "tab", "down":
		m.focusNext()
		return m, nil
	case "shift+tab", "up":
		m.focusPrev()
		return m, nil
	case "enter":
		if m.focus < len(m.inputs)-1 {
			m.focusNext()
			return m, nil
		}
		m.busy = true
		return m, m.submitFormCmd(ctx)
	}
	return m.updateFocusedInput(key)
}

func (m model) updateDelete(ctx context.Context, key tea.KeyMsg) (model, tea.Cmd) {
	switch key.String() {
	case "y":
		if m.current == nil {
			m.screen = screenList
			return m, nil
		}
		m.busy = true
		return m, m.deleteCmd(ctx, *m.current)
	case "n", "esc":
		m.screen = screenList
	}
	return m, nil
}

func (m model) updateSaveBinary(ctx context.Context, key tea.KeyMsg) (model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.screen = screenDetail
		return m, nil
	case "enter":
		if m.current == nil {
			m.screen = screenDetail
			return m, nil
		}
		m.busy = true
		return m, m.saveBinaryCmd(ctx, *m.current, m.inputs[0].Value())
	}
	return m.updateFocusedInput(key)
}

func (m model) submitAuthCmd(ctx context.Context) tea.Cmd {
	login := m.inputs[0].Value()
	loginPassword := m.inputs[1].Value()
	masterPassword := m.inputs[2].Value()
	if m.authMode == authModeRegister && masterPassword != m.inputs[3].Value() {
		return func() tea.Msg { return authDoneMsg{err: clientapp.ErrMasterPasswordsMismatch} }
	}

	return func() tea.Msg {
		var (
			session core.Session
			err     error
		)
		if m.authMode == authModeRegister {
			session, err = m.deps.authService.Register(ctx, core.RegisterInput{
				Login:          strings.TrimSpace(login),
				LoginPassword:  loginPassword,
				MasterPassword: masterPassword,
			})
		} else {
			session, err = m.deps.authService.Login(ctx, core.LoginInput{
				Login:          strings.TrimSpace(login),
				LoginPassword:  loginPassword,
				MasterPassword: masterPassword,
			})
		}
		return authDoneMsg{session: session, err: err}
	}
}

func (m model) loadSecretsCmd(ctx context.Context, includeDeleted bool) tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return listDoneMsg{err: clientapp.ErrVaultSessionClosed} }
	}
	return func() tea.Msg {
		secrets, err := m.deps.vaultService.ListSecrets(ctx, session, core.ListSecretsInput{IncludeDeleted: includeDeleted})
		return listDoneMsg{secrets: secrets, err: err}
	}
}

func (m model) getSecretCmd(ctx context.Context, id string) tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return secretDoneMsg{err: clientapp.ErrVaultSessionClosed} }
	}
	return func() tea.Msg {
		secret, err := m.deps.vaultService.GetSecret(ctx, session, core.GetSecretInput{ID: id})
		return secretDoneMsg{secret: secret, err: err}
	}
}

func (m model) syncCmd(ctx context.Context) tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return syncDoneMsg{err: clientapp.ErrVaultSessionClosed} }
	}
	return func() tea.Msg {
		result, err := m.deps.vaultService.SyncSecrets(ctx, session, core.SyncSecretsInput{})
		return syncDoneMsg{count: len(result.Secrets), err: err}
	}
}

func (m model) deleteCmd(ctx context.Context, secret core.Secret) tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return deleteDoneMsg{err: clientapp.ErrVaultSessionClosed} }
	}
	return func() tea.Msg {
		_, err := m.deps.vaultService.DeleteSecret(ctx, session, core.DeleteSecretInput{
			ID:              secret.ID,
			ExpectedVersion: secret.Version,
		})
		return deleteDoneMsg{err: err}
	}
}

func (m model) submitFormCmd(ctx context.Context) tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return secretDoneMsg{err: clientapp.ErrVaultSessionClosed} }
	}

	input, err := m.secretInputFromForm(ctx)
	if err != nil {
		return func() tea.Msg { return secretDoneMsg{err: err} }
	}

	if m.formMode == formModeUpdate {
		return func() tea.Msg {
			secret, err := m.deps.vaultService.UpdateSecret(ctx, session, core.UpdateSecretInput{
				ID:                   m.editID,
				ExpectedVersion:      m.editVer,
				Type:                 input.Type,
				Metadata:             input.Metadata,
				Payload:              input.Payload,
				PayloadSchemaVersion: input.PayloadSchemaVersion,
			})
			return secretDoneMsg{secret: secret, err: err}
		}
	}

	return func() tea.Msg {
		secret, err := m.deps.vaultService.CreateSecret(ctx, session, input)
		return secretDoneMsg{secret: secret, err: err}
	}
}

func (m model) saveBinaryCmd(ctx context.Context, secret core.Secret, outputPath string) tea.Cmd {
	return func() tea.Msg {
		binaryPayload, err := core.DecodeBinaryPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return saveDoneMsg{err: fmt.Errorf("decode binary payload: %w", err)}
		}
		path, err := resolveBinaryOutputPath(outputPath, binaryPayload.FileName)
		if err != nil {
			return saveDoneMsg{err: err}
		}

		if m.deps.blobService == nil {
			return saveDoneMsg{err: clientapp.ErrBlobServiceRequired}
		}
		session, ok := m.deps.sessionState.Session()
		if !ok {
			return saveDoneMsg{err: clientapp.ErrVaultSessionClosed}
		}

		if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return saveDoneMsg{err: fmt.Errorf("create output dir: %w", err)}
		}

		data, err := m.deps.blobService.DownloadBinary(ctx, session, core.DownloadBinaryInput{
			Payload: binaryPayload,
		})
		if err != nil {
			return saveDoneMsg{err: fmt.Errorf("download binary blob: %w", err)}
		}

		if err = os.WriteFile(path, data, 0o600); err != nil {
			return saveDoneMsg{err: fmt.Errorf("write binary file: %w", err)}
		}
		return saveDoneMsg{path: path}
	}
}

func resolveBinaryOutputPath(outputDir string, fileName string) (string, error) {
	dir, err := normalizeBinaryOutputPath(outputDir)
	if err != nil {
		return "", err
	}

	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("%w: %s", clientapp.ErrOutputDirectoryNotDirectory, dir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("check output file: %w", err)
	}

	path := filepath.Join(dir, safeBinaryFileName(fileName))
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%w: %s", clientapp.ErrOutputFileExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("check output file: %w", err)
	}

	return path, nil
}

func normalizeBinaryOutputPath(outputPath string) (string, error) {
	path := strings.TrimSpace(outputPath)
	if path == "" {
		return "", clientapp.ErrOutputDirectoryRequired
	}

	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		if path == "~" {
			return filepath.Clean(home), nil
		}
		return filepath.Clean(filepath.Join(home, strings.TrimPrefix(path, "~/"))), nil
	}

	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		cleanHome := filepath.Clean(home)
		homeWithoutRoot := strings.TrimPrefix(cleanHome, string(os.PathSeparator))
		if !filepath.IsAbs(path) {
			if path == homeWithoutRoot || strings.HasPrefix(path, homeWithoutRoot+string(os.PathSeparator)) {
				path = string(os.PathSeparator) + path
			}
		}

		duplicateHome := cleanHome + string(os.PathSeparator) + homeWithoutRoot
		if path == duplicateHome || strings.HasPrefix(path, duplicateHome+string(os.PathSeparator)) {
			path = filepath.Clean(cleanHome + strings.TrimPrefix(path, duplicateHome))
		}
	}

	return filepath.Clean(path), nil
}

func safeBinaryFileName(fileName string) string {
	name := filepath.Base(strings.TrimSpace(fileName))
	if name == "." || name == string(os.PathSeparator) {
		return "binary"
	}

	return name
}

func otpTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return otpTickMsg(t)
	})
}

func (m model) startCreateForm(kind secretKind) (model, tea.Cmd) {
	m.formMode = formModeCreate
	m.formKind = kind
	m.editID = ""
	m.editVer = 0
	m.inputs = inputsForKind(kind)
	m.focus = 0
	m.inputs[0].Focus()
	m.screen = screenForm
	return m, nil
}

func (m model) startUpdateForm(secret core.Secret) (model, tea.Cmd) {
	m.formMode = formModeUpdate
	m.formKind = kindFromSecretType(secret.Type)
	m.editID = secret.ID
	m.editVer = secret.Version
	inputs, err := inputsFromSecret(secret)
	if err != nil {
		m.setError(err)
		return m, nil
	}
	m.inputs = inputs
	m.focus = 0
	m.inputs[0].Focus()
	m.screen = screenForm
	return m, nil
}

func (m model) secretInputFromForm(ctx context.Context) (core.CreateSecretInput, error) {
	title := m.inputs[0].Value()
	metadata, err := encodeTextSecretMetadata(title)
	if err != nil {
		return core.CreateSecretInput{}, err
	}

	switch m.formKind {
	case secretKindText:
		payload, version, err := core.EncodeTextPayload(core.TextPayload{Text: m.inputs[1].Value()})
		return createInput(core.SecretTypeText, metadata, payload, version), err
	case secretKindLoginPassword:
		payload, version, err := core.EncodeLoginPasswordPayload(core.LoginPasswordPayload{
			Login:    m.inputs[1].Value(),
			Password: m.inputs[2].Value(),
			URL:      strings.TrimSpace(m.inputs[3].Value()),
			Notes:    strings.TrimSpace(m.inputs[4].Value()),
		})
		return createInput(core.SecretTypeLoginPassword, metadata, payload, version), err
	case secretKindBankCard:
		payload, version, err := core.EncodeBankCardPayload(core.BankCardPayload{
			Number:          m.inputs[1].Value(),
			CardholderName:  m.inputs[2].Value(),
			ExpirationMonth: m.inputs[3].Value(),
			ExpirationYear:  m.inputs[4].Value(),
			CVV:             m.inputs[5].Value(),
			Notes:           strings.TrimSpace(m.inputs[6].Value()),
		})
		return createInput(core.SecretTypeBankCard, metadata, payload, version), err
	case secretKindBinary:
		if m.deps.blobService == nil {
			return core.CreateSecretInput{}, clientapp.ErrBlobServiceRequired
		}
		session, ok := m.deps.sessionState.Session()
		if !ok {
			return core.CreateSecretInput{}, clientapp.ErrVaultSessionClosed
		}

		data, err := os.ReadFile(m.inputs[1].Value())
		if err != nil {
			return core.CreateSecretInput{}, fmt.Errorf("read binary file: %w", err)
		}

		binaryPayload, err := m.deps.blobService.UploadBinary(ctx, session, core.UploadBinaryInput{
			FileName:    filepath.Base(m.inputs[1].Value()),
			ContentType: strings.TrimSpace(m.inputs[2].Value()),
			Data:        data,
		})
		if err != nil {
			return core.CreateSecretInput{}, fmt.Errorf("upload binary blob: %w", err)
		}

		payload, version, err := core.EncodeBinaryPayload(binaryPayload)
		return createInput(core.SecretTypeBinary, metadata, payload, version), err
	case secretKindOTP:
		digits, err := parseOptionalUint32(m.inputs[4].Value(), 6)
		if err != nil {
			return core.CreateSecretInput{}, fmt.Errorf("parse otp digits: %w", err)
		}
		period, err := parseOptionalUint32(m.inputs[5].Value(), core.DefaultOTPPeriodSeconds)
		if err != nil {
			return core.CreateSecretInput{}, fmt.Errorf("parse otp period: %w", err)
		}
		payload, version, err := core.EncodeOTPPayload(core.OTPPayload{
			Issuer:        strings.TrimSpace(m.inputs[1].Value()),
			AccountName:   strings.TrimSpace(m.inputs[2].Value()),
			Secret:        strings.TrimSpace(m.inputs[3].Value()),
			Algorithm:     strings.TrimSpace(m.inputs[6].Value()),
			Digits:        digits,
			PeriodSeconds: period,
			Notes:         strings.TrimSpace(m.inputs[7].Value()),
		})
		return createInput(core.SecretTypeOTP, metadata, payload, version), err
	default:
		return core.CreateSecretInput{}, fmt.Errorf("unsupported secret type: %s", m.formKind)
	}
}

func (m model) viewWelcome() string {
	lines := []string{
		activeStyle.Render(strings.TrimRight(banner, "\n")),
		titleStyle.Render("Команды"),
		"Enter  перейти к входу",
		"Ctrl+R  режим регистрации",
		"Ctrl+L  режим входа",
		"N  создать секрет",
		"T/P/C/B/O  text, login/password, bank card, binary, OTP",
		"Enter  открыть или отправить форму",
		"U  обновить выбранный секрет",
		"D  удалить выбранный секрет",
		"R  обновить список",
		"S  синхронизировать vault",
		"Esc  назад",
		"Q  выйти из TUI",
	}
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n"))
}

func (m model) viewAuth() string {
	mode := "Вход"
	if m.authMode == authModeRegister {
		mode = "Регистрация"
	}
	lines := []string{titleStyle.Render("GophKeeper TUI"), mutedStyle.Render(mode)}
	for _, input := range m.inputs {
		lines = append(lines, input.View())
	}
	lines = append(lines, mutedStyle.Render("Ctrl+L вход  Ctrl+R регистрация  Enter далее или отправить"))
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n\n"))
}

func (m model) viewList() string {
	lines := []string{titleStyle.Render("Vault")}
	if len(m.secrets) == 0 {
		lines = append(lines, mutedStyle.Render("Нет секретов"))
	}
	for i, secret := range m.secrets {
		prefix := "  "
		style := lipgloss.NewStyle()
		if i == m.selected {
			prefix = "> "
			style = activeStyle
		}
		lines = append(lines, style.Render(prefix+m.secretRow(secret)))
	}
	lines = append(lines, mutedStyle.Render("Enter открыть секрет, для OTP показать код  N создать  U обновить  D удалить  R обновить  S синхронизировать  Q стартовый экран"))
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n"))
}

func (m model) viewDetail() string {
	lines := []string{titleStyle.Render("Secret"), m.detail.View()}
	lines = append(lines, mutedStyle.Render("Esc назад  U обновить  D удалить  S сохранить binary"))
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n"))
}

func (m model) viewTypeSelect() string {
	lines := []string{
		titleStyle.Render("Новый секрет"),
		"T Текст",
		"P Логин и пароль",
		"C Банковская карта",
		"B Файл или binary данные",
		"O OTP одноразовый пароль",
		mutedStyle.Render("Esc назад"),
	}
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n"))
}

func (m model) viewForm() string {
	title := "Создание: " + formKindLabel(m.formKind)
	if m.formMode == formModeUpdate {
		title = "Обновление: " + formKindLabel(m.formKind)
	}
	lines := []string{titleStyle.Render(title)}
	lines = append(lines, mutedStyle.Render(formHelp(m.formKind)))
	for _, input := range m.inputs {
		lines = append(lines, input.View())
	}
	lines = append(lines, mutedStyle.Render("Enter далее или сохранить  Esc отмена"))
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n\n"))
}

func (m model) viewDelete() string {
	title := "<unknown>"
	if m.current != nil {
		title = secretTitle(*m.current)
	}
	lines := []string{
		titleStyle.Render("Удаление секрета"),
		"Удалить: " + title,
		mutedStyle.Render("Y удалить  N отмена"),
	}
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n\n"))
}

func (m model) viewSaveBinary() string {
	lines := []string{titleStyle.Render("Сохранение binary"), m.inputs[0].View(), mutedStyle.Render("Enter сохранить  Esc отмена")}
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n\n"))
}

func (m model) viewStatus() string {
	status := m.status
	if m.busy {
		status = "выполняется операция"
	}
	if status == "" {
		status = "готово"
	}
	style := okStyle
	if m.isError {
		style = errorStyle
	}
	if m.busy {
		style = mutedStyle
	}
	return lipgloss.NewStyle().Padding(0, 2).Render(style.Render(status))
}

func (m model) renderSecretDetail(secret core.Secret) string {
	lines := []string{
		"ID: " + secret.ID,
		fmt.Sprintf("Version: %d", secret.Version),
		"Type: " + secretTypeLabel(secret.Type),
		"Title: " + secretTitle(secret),
		"",
	}

	switch secret.Type {
	case core.SecretTypeText:
		if value, err := core.DecodeTextPayload(secret.Payload, secret.PayloadSchemaVersion); err == nil {
			lines = append(lines, value.Text)
		}
	case core.SecretTypeLoginPassword:
		if value, err := core.DecodeLoginPasswordPayload(secret.Payload, secret.PayloadSchemaVersion); err == nil {
			lines = append(lines, "Login: "+value.Login, "Password: "+value.Password, "URL: "+value.URL, "Notes: "+value.Notes)
		}
	case core.SecretTypeBankCard:
		if value, err := core.DecodeBankCardPayload(secret.Payload, secret.PayloadSchemaVersion); err == nil {
			lines = append(lines, "Number: "+value.Number, "Cardholder: "+value.CardholderName, "Expires: "+value.ExpirationMonth+"/"+value.ExpirationYear, "CVV: "+value.CVV, "Notes: "+value.Notes)
		}
	case core.SecretTypeBinary:
		if value, err := core.DecodeBinaryPayload(secret.Payload, secret.PayloadSchemaVersion); err == nil {
			lines = append(lines, "File: "+value.FileName, "Content-Type: "+value.ContentType, fmt.Sprintf("Size: %d bytes", value.SizeBytes), "SHA256: "+value.ChecksumSHA256)
		}
	case core.SecretTypeOTP:
		if value, err := core.DecodeOTPPayload(secret.Payload, secret.PayloadSchemaVersion); err == nil {
			code, codeErr := core.CurrentOTPCode(value, time.Now())
			lines = append(lines, "Сервис: "+value.Issuer, "Аккаунт: "+value.AccountName, "OTP secret: "+core.MaskOTPSecret(value.Secret))
			if codeErr == nil {
				progress := otpProgress(code.RemainingSeconds, code.PeriodSeconds)
				lines = append(lines, "Текущий OTP-код: "+code.Value, fmt.Sprintf("До смены кода: %d секунд %s", code.RemainingSeconds, progress))
			} else {
				lines = append(lines, "OTP-код: "+clientapp.UserFacingError(codeErr))
			}
		}
	}

	return strings.Join(lines, "\n")
}

func (m model) secretRow(secret core.Secret) string {
	title := secretTitle(secret)
	if secret.Type == core.SecretTypeOTP {
		if value, err := core.DecodeOTPPayload(secret.Payload, secret.PayloadSchemaVersion); err == nil {
			code, codeErr := core.CurrentOTPCode(value, time.Now())
			account := strings.TrimSpace(value.Issuer + " " + value.AccountName)
			if codeErr == nil {
				return fmt.Sprintf("%s | v%d | otp | %s | %ds | %s", secret.ID, secret.Version, account, code.RemainingSeconds, title)
			}
			return fmt.Sprintf("%s | v%d | otp | %s | %s", secret.ID, secret.Version, account, title)
		}
	}
	return fmt.Sprintf("%s | v%d | %s | %s", secret.ID, secret.Version, secretTypeLabel(secret.Type), title)
}

func (m *model) setError(err error) {
	m.status = clientapp.UserFacingError(err)
	m.isError = true
}

func (m *model) statusOK(value string) {
	m.status = value
	m.isError = false
}

func (m *model) resetToWelcome() {
	m.deps.sessionState.Clear()
	m.screen = screenWelcome
	m.busy = false
	m.status = ""
	m.isError = false
	m.authMode = authModeLogin
	m.secrets = nil
	m.selected = 0
	m.current = nil
	m.formMode = formModeCreate
	m.formKind = ""
	m.editID = ""
	m.editVer = 0
	m.setAuthInputs()
}

func (m *model) focusNext() {
	if len(m.inputs) == 0 {
		return
	}
	m.inputs[m.focus].Blur()
	m.focus = (m.focus + 1) % len(m.inputs)
	m.inputs[m.focus].Focus()
}

func (m *model) focusPrev() {
	if len(m.inputs) == 0 {
		return
	}
	m.inputs[m.focus].Blur()
	m.focus--
	if m.focus < 0 {
		m.focus = len(m.inputs) - 1
	}
	m.inputs[m.focus].Focus()
}

func (m model) updateFocusedInput(key tea.KeyMsg) (model, tea.Cmd) {
	var cmd tea.Cmd
	m.inputs[m.focus], cmd = m.inputs[m.focus].Update(key)
	return m, cmd
}

func makeInputs(labels []string, hidden map[int]bool) []textinput.Model {
	inputs := make([]textinput.Model, 0, len(labels))
	for i, label := range labels {
		input := textinput.New()
		input.Placeholder = inputPlaceholder(label)
		input.Prompt = label + ": "
		input.CharLimit = 2048
		input.Width = 64
		if hidden != nil && hidden[i] {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '*'
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func inputPlaceholder(label string) string {
	switch label {
	case "Логин":
		return "user@example.com"
	case "Пароль входа":
		return "пароль для входа на сервер"
	case "Мастер-пароль":
		return "пароль для расшифровки vault"
	case "Повтор мастер-пароля":
		return "повторите мастер-пароль"
	case "Название":
		return "понятное имя секрета"
	case "Текст секрета":
		return "любой текст, который нужно хранить"
	case "Логин секрета":
		return "логин от сайта или сервиса"
	case "Пароль секрета":
		return "пароль от сайта или сервиса"
	case "URL":
		return "https://example.com"
	case "Заметки":
		return "необязательное описание"
	case "Номер карты":
		return "4111111111111111"
	case "Имя владельца":
		return "IVAN IVANOV"
	case "Месяц окончания":
		return "05"
	case "Год окончания":
		return "2030"
	case "CVV":
		return "123"
	case "Путь к файлу":
		return "/path/to/file"
	case "Папка для сохранения":
		return "~/Downloads"
	case "Content type":
		return "text/plain или application/octet-stream"
	case "Сервис":
		return "GitHub, Google, Почта"
	case "Аккаунт":
		return "user@example.com"
	case "OTP secret":
		return "ключ ручного ввода или secret из otpauth URI"
	case "Длина OTP-кода":
		return "6 или 8 цифр"
	case "Период секунд":
		return "по умолчанию 30"
	case "Алгоритм":
		return "SHA1, SHA256 или SHA512"
	default:
		return label
	}
}

func inputsForKind(kind secretKind) []textinput.Model {
	switch kind {
	case secretKindText:
		return makeInputs([]string{"Название", "Текст секрета"}, nil)
	case secretKindLoginPassword:
		return makeInputs([]string{"Название", "Логин секрета", "Пароль секрета", "URL", "Заметки"}, map[int]bool{2: true})
	case secretKindBankCard:
		return makeInputs([]string{"Название", "Номер карты", "Имя владельца", "Месяц окончания", "Год окончания", "CVV", "Заметки"}, map[int]bool{5: true})
	case secretKindBinary:
		return makeInputs([]string{"Название", "Путь к файлу", "Content type"}, nil)
	case secretKindOTP:
		inputs := makeInputs([]string{"Название", "Сервис", "Аккаунт", "OTP secret", "Длина OTP-кода", "Период секунд", "Алгоритм", "Заметки"}, map[int]bool{3: true})
		inputs[4].SetValue("6")
		inputs[5].SetValue(strconv.Itoa(core.DefaultOTPPeriodSeconds))
		inputs[6].SetValue("SHA1")
		return inputs
	default:
		return makeInputs([]string{"Название"}, nil)
	}
}

func inputsFromSecret(secret core.Secret) ([]textinput.Model, error) {
	kind := kindFromSecretType(secret.Type)
	inputs := inputsForKind(kind)
	inputs[0].SetValue(secretTitle(secret))

	switch secret.Type {
	case core.SecretTypeText:
		value, err := core.DecodeTextPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return nil, err
		}
		inputs[1].SetValue(value.Text)
	case core.SecretTypeLoginPassword:
		value, err := core.DecodeLoginPasswordPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return nil, err
		}
		inputs[1].SetValue(value.Login)
		inputs[2].SetValue(value.Password)
		inputs[3].SetValue(value.URL)
		inputs[4].SetValue(value.Notes)
	case core.SecretTypeBankCard:
		value, err := core.DecodeBankCardPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return nil, err
		}
		inputs[1].SetValue(value.Number)
		inputs[2].SetValue(value.CardholderName)
		inputs[3].SetValue(value.ExpirationMonth)
		inputs[4].SetValue(value.ExpirationYear)
		inputs[5].SetValue(value.CVV)
		inputs[6].SetValue(value.Notes)
	case core.SecretTypeBinary:
		value, err := core.DecodeBinaryPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return nil, err
		}
		inputs[1].SetValue(value.FileName)
		inputs[2].SetValue(value.ContentType)
	case core.SecretTypeOTP:
		value, err := core.DecodeOTPPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return nil, err
		}
		inputs[1].SetValue(value.Issuer)
		inputs[2].SetValue(value.AccountName)
		inputs[3].SetValue(value.Secret)
		inputs[4].SetValue(strconv.Itoa(int(value.Digits)))
		inputs[5].SetValue(strconv.Itoa(int(value.PeriodSeconds)))
		inputs[6].SetValue(value.Algorithm)
		inputs[7].SetValue(value.Notes)
	}

	return inputs, nil
}

func formKindLabel(kind secretKind) string {
	switch kind {
	case secretKindText:
		return "текст"
	case secretKindLoginPassword:
		return "логин и пароль"
	case secretKindBankCard:
		return "банковская карта"
	case secretKindBinary:
		return "файл или binary данные"
	case secretKindOTP:
		return "OTP одноразовый пароль"
	default:
		return string(kind)
	}
}

func formHelp(kind secretKind) string {
	switch kind {
	case secretKindText:
		return strings.Join([]string{
			"Название: короткое имя секрета для списка, например Рабочая заметка",
			"Текст секрета: любой текст, который нужно хранить приватно",
			"Текст шифруется на клиенте и не отправляется на сервер в открытом виде",
		}, "\n")
	case secretKindLoginPassword:
		return strings.Join([]string{
			"Название: имя записи для списка, например GitHub account",
			"Логин секрета: login или email от сайта или сервиса",
			"Пароль секрета: пароль от этого сайта или сервиса, не пароль входа в GophKeeper",
			"URL: адрес сайта, можно оставить пустым",
			"Заметки: любое дополнительное описание, можно оставить пустым",
		}, "\n")
	case secretKindBankCard:
		return strings.Join([]string{
			"Название: имя карты для списка, например Зарплатная карта",
			"Номер карты: номер без пробелов или с пробелами, как удобно вводить",
			"Имя владельца: имя на карте",
			"Месяц окончания: две цифры, например 05",
			"Год окончания: четыре цифры, например 2030",
			"CVV: код с обратной стороны карты, поле скрыто при вводе",
			"Заметки: банк или назначение карты, можно оставить пустым",
		}, "\n")
	case secretKindBinary:
		return strings.Join([]string{
			"Название: имя файла или понятное имя записи для списка",
			"Путь к файлу: локальный путь к файлу, который нужно сохранить",
			"Content type: тип содержимого, например text/plain или application/octet-stream",
			"TUI прочитает файл, зашифрует содержимое и сохранит metadata",
		}, "\n")
	case secretKindOTP:
		return strings.Join([]string{
			"Название: имя OTP записи для списка, например Почта OTP",
			"Сервис: кто выдал код, например Google, GitHub, Почта",
			"Аккаунт: login или email, для которого создан OTP",
			"OTP secret: ключ ручного ввода из 2FA или значение secret из otpauth URI",
			"Длина OTP-кода: по умолчанию 6",
			"Период секунд: время жизни кода, значение по умолчанию 30",
			"Алгоритм: значение по умолчанию SHA1",
			"Заметки: дополнительное описание, можно оставить пустым",
			"После сохранения откроется detail, где будет строка Текущий OTP-код",
		}, "\n")
	default:
		return ""
	}
}

func createInput(secretType core.SecretType, metadata []byte, payload []byte, version uint32) core.CreateSecretInput {
	return core.CreateSecretInput{
		Type:                 secretType,
		Metadata:             metadata,
		Payload:              payload,
		PayloadSchemaVersion: version,
	}
}

func encodeTextSecretMetadata(title string) ([]byte, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		return nil, fmt.Errorf("title is required")
	}

	raw, err := json.Marshal(struct {
		Title string `json:"title"`
	}{Title: title})
	if err != nil {
		return nil, fmt.Errorf("encode secret metadata: %w", err)
	}
	return raw, nil
}

func secretTitle(secret core.Secret) string {
	var metadata struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(secret.Metadata, &metadata); err != nil {
		return "<без названия>"
	}
	if strings.TrimSpace(metadata.Title) == "" {
		return "<без названия>"
	}
	return metadata.Title
}

func secretTypeLabel(secretType core.SecretType) string {
	switch secretType {
	case core.SecretTypeText:
		return "text"
	case core.SecretTypeLoginPassword:
		return "login-password"
	case core.SecretTypeBankCard:
		return "bank-card"
	case core.SecretTypeBinary:
		return "binary"
	case core.SecretTypeOTP:
		return "otp"
	default:
		return "unknown"
	}
}

func kindFromSecretType(secretType core.SecretType) secretKind {
	switch secretType {
	case core.SecretTypeText:
		return secretKindText
	case core.SecretTypeLoginPassword:
		return secretKindLoginPassword
	case core.SecretTypeBankCard:
		return secretKindBankCard
	case core.SecretTypeBinary:
		return secretKindBinary
	case core.SecretTypeOTP:
		return secretKindOTP
	default:
		return secretKindText
	}
}

func parseOptionalUint32(value string, fallback uint32) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}

func otpProgress(remaining uint32, period uint32) string {
	if period == 0 {
		return ""
	}
	done := int((period - remaining) * 10 / period)
	if done < 0 {
		done = 0
	}
	if done > 10 {
		done = 10
	}
	return "[" + strings.Repeat("=", done) + strings.Repeat(".", 10-done) + "]"
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
