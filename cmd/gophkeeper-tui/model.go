package main

import (
	"context"
	"encoding/json"
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

type sessionState interface {
	SetSession(core.Session) error
	Session() (core.Session, bool)
	Clear()
}

type appDeps struct {
	authService  authService
	vaultService vaultService
	sessionState sessionState
}

type screen int

const (
	screenAuth screen = iota
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

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	mutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	activeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
)

type model struct {
	ctx     context.Context
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

func newModel(ctx context.Context, deps appDeps) model {
	m := model{
		ctx:    ctx,
		deps:   deps,
		screen: screenAuth,
		detail: viewport.New(80, 20),
	}
	m.setAuthInputs()
	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		return m, m.loadSecretsCmd(false)
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
			return m, m.loadSecretsCmd(false)
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
		return m, m.loadSecretsCmd(false)
	case syncDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.statusOK(fmt.Sprintf("синхронизация выполнена, изменений: %d", msg.count))
		return m, m.loadSecretsCmd(false)
	case saveDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.statusOK("binary сохранен: " + msg.path)
		m.screen = screenDetail
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
	case screenAuth:
		return m.updateAuth(key)
	case screenList:
		return m.updateList(key)
	case screenDetail:
		return m.updateDetail(key)
	case screenTypeSelect:
		return m.updateTypeSelect(key)
	case screenForm:
		return m.updateForm(key)
	case screenDelete:
		return m.updateDelete(key)
	case screenSaveBinary:
		return m.updateSaveBinary(key)
	default:
		return m, nil
	}
}

func (m model) View() string {
	body := ""
	switch m.screen {
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
	labels := []string{"Login", "Login password", "Master password"}
	if m.authMode == authModeRegister {
		labels = append(labels, "Repeat master password")
	}
	m.inputs = makeInputs(labels, map[int]bool{1: true, 2: true, 3: true})
	m.focus = 0
	m.inputs[0].Focus()
}

func (m model) updateAuth(key tea.KeyMsg) (tea.Model, tea.Cmd) {
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
		return m, m.submitAuthCmd()
	}
	return m.updateFocusedInput(key)
}

func (m model) updateList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "q":
		return m, tea.Quit
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
		return m, m.loadSecretsCmd(false)
	case "s":
		m.busy = true
		return m, m.syncCmd()
	case "n":
		m.screen = screenTypeSelect
	case "enter":
		if len(m.secrets) > 0 {
			m.busy = true
			return m, m.getSecretCmd(m.secrets[m.selected].ID)
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

func (m model) updateDetail(key tea.KeyMsg) (tea.Model, tea.Cmd) {
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
			m.inputs = makeInputs([]string{"Output path"}, nil)
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

func (m model) updateTypeSelect(key tea.KeyMsg) (tea.Model, tea.Cmd) {
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

func (m model) updateForm(key tea.KeyMsg) (tea.Model, tea.Cmd) {
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
		return m, m.submitFormCmd()
	}
	return m.updateFocusedInput(key)
}

func (m model) updateDelete(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "y":
		if m.current == nil {
			m.screen = screenList
			return m, nil
		}
		m.busy = true
		return m, m.deleteCmd(*m.current)
	case "n", "esc":
		m.screen = screenList
	}
	return m, nil
}

func (m model) updateSaveBinary(key tea.KeyMsg) (tea.Model, tea.Cmd) {
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
		return m, m.saveBinaryCmd(*m.current, m.inputs[0].Value())
	}
	return m.updateFocusedInput(key)
}

func (m model) submitAuthCmd() tea.Cmd {
	login := m.inputs[0].Value()
	loginPassword := m.inputs[1].Value()
	masterPassword := m.inputs[2].Value()
	if m.authMode == authModeRegister && masterPassword != m.inputs[3].Value() {
		return func() tea.Msg { return authDoneMsg{err: fmt.Errorf("master passwords do not match")} }
	}

	return func() tea.Msg {
		var (
			session core.Session
			err     error
		)
		if m.authMode == authModeRegister {
			session, err = m.deps.authService.Register(m.ctx, core.RegisterInput{
				Login:          strings.TrimSpace(login),
				LoginPassword:  loginPassword,
				MasterPassword: masterPassword,
			})
		} else {
			session, err = m.deps.authService.Login(m.ctx, core.LoginInput{
				Login:          strings.TrimSpace(login),
				LoginPassword:  loginPassword,
				MasterPassword: masterPassword,
			})
		}
		return authDoneMsg{session: session, err: err}
	}
}

func (m model) loadSecretsCmd(includeDeleted bool) tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return listDoneMsg{err: fmt.Errorf("vault session is not open")} }
	}
	return func() tea.Msg {
		secrets, err := m.deps.vaultService.ListSecrets(m.ctx, session, core.ListSecretsInput{IncludeDeleted: includeDeleted})
		return listDoneMsg{secrets: secrets, err: err}
	}
}

func (m model) getSecretCmd(id string) tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return secretDoneMsg{err: fmt.Errorf("vault session is not open")} }
	}
	return func() tea.Msg {
		secret, err := m.deps.vaultService.GetSecret(m.ctx, session, core.GetSecretInput{ID: id})
		return secretDoneMsg{secret: secret, err: err}
	}
}

func (m model) syncCmd() tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return syncDoneMsg{err: fmt.Errorf("vault session is not open")} }
	}
	return func() tea.Msg {
		result, err := m.deps.vaultService.SyncSecrets(m.ctx, session, core.SyncSecretsInput{})
		return syncDoneMsg{count: len(result.Secrets), err: err}
	}
}

func (m model) deleteCmd(secret core.Secret) tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return deleteDoneMsg{err: fmt.Errorf("vault session is not open")} }
	}
	return func() tea.Msg {
		_, err := m.deps.vaultService.DeleteSecret(m.ctx, session, core.DeleteSecretInput{
			ID:              secret.ID,
			ExpectedVersion: secret.Version,
		})
		return deleteDoneMsg{err: err}
	}
}

func (m model) submitFormCmd() tea.Cmd {
	session, ok := m.deps.sessionState.Session()
	if !ok {
		return func() tea.Msg { return secretDoneMsg{err: fmt.Errorf("vault session is not open")} }
	}

	input, err := m.secretInputFromForm()
	if err != nil {
		return func() tea.Msg { return secretDoneMsg{err: err} }
	}

	if m.formMode == formModeUpdate {
		return func() tea.Msg {
			secret, err := m.deps.vaultService.UpdateSecret(m.ctx, session, core.UpdateSecretInput{
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
		secret, err := m.deps.vaultService.CreateSecret(m.ctx, session, input)
		return secretDoneMsg{secret: secret, err: err}
	}
}

func (m model) saveBinaryCmd(secret core.Secret, outputPath string) tea.Cmd {
	return func() tea.Msg {
		path := strings.TrimSpace(outputPath)
		if path == "" {
			return saveDoneMsg{err: fmt.Errorf("output path is required")}
		}
		binaryPayload, err := core.DecodeBinaryPayload(secret.Payload, secret.PayloadSchemaVersion)
		if err != nil {
			return saveDoneMsg{err: fmt.Errorf("decode binary payload: %w", err)}
		}
		if _, err = os.Stat(path); err == nil {
			return saveDoneMsg{err: fmt.Errorf("output file already exists: %s", path)}
		}
		if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return saveDoneMsg{err: fmt.Errorf("create output dir: %w", err)}
		}
		if err = os.WriteFile(path, binaryPayload.Data, 0o600); err != nil {
			return saveDoneMsg{err: fmt.Errorf("write binary file: %w", err)}
		}
		return saveDoneMsg{path: path}
	}
}

func (m model) startCreateForm(kind secretKind) (tea.Model, tea.Cmd) {
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

func (m model) startUpdateForm(secret core.Secret) (tea.Model, tea.Cmd) {
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

func (m model) secretInputFromForm() (core.CreateSecretInput, error) {
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
		data, err := os.ReadFile(m.inputs[1].Value())
		if err != nil {
			return core.CreateSecretInput{}, fmt.Errorf("read binary file: %w", err)
		}
		payload, version, err := core.EncodeBinaryPayload(core.BinaryPayload{
			FileName:    filepath.Base(m.inputs[1].Value()),
			ContentType: strings.TrimSpace(m.inputs[2].Value()),
			Data:        data,
		})
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

func (m model) viewAuth() string {
	mode := "Login"
	if m.authMode == authModeRegister {
		mode = "Register"
	}
	lines := []string{titleStyle.Render("GophKeeper TUI"), mutedStyle.Render(mode)}
	for _, input := range m.inputs {
		lines = append(lines, input.View())
	}
	lines = append(lines, mutedStyle.Render("Ctrl+L Login  Ctrl+R Register  Enter Submit"))
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
	lines = append(lines, mutedStyle.Render("Enter Open  N New  U Update  D Delete  R Refresh  S Sync  Q Quit"))
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n"))
}

func (m model) viewDetail() string {
	lines := []string{titleStyle.Render("Secret"), m.detail.View()}
	lines = append(lines, mutedStyle.Render("Esc Back  U Update  D Delete  S Save binary"))
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n"))
}

func (m model) viewTypeSelect() string {
	lines := []string{
		titleStyle.Render("New secret"),
		"T Text",
		"P Login/password",
		"C Bank card",
		"B Binary",
		"O OTP",
	}
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n"))
}

func (m model) viewForm() string {
	title := "Create " + string(m.formKind)
	if m.formMode == formModeUpdate {
		title = "Update " + string(m.formKind)
	}
	lines := []string{titleStyle.Render(title)}
	for _, input := range m.inputs {
		lines = append(lines, input.View())
	}
	lines = append(lines, mutedStyle.Render("Enter Submit  Esc Cancel"))
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n\n"))
}

func (m model) viewDelete() string {
	title := "<unknown>"
	if m.current != nil {
		title = secretTitle(*m.current)
	}
	lines := []string{
		titleStyle.Render("Delete secret"),
		"Удалить: " + title,
		mutedStyle.Render("Y Delete  N Cancel"),
	}
	return lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(lines, "\n\n"))
}

func (m model) viewSaveBinary() string {
	lines := []string{titleStyle.Render("Save binary"), m.inputs[0].View(), mutedStyle.Render("Enter Save  Esc Cancel")}
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
			lines = append(lines, "Issuer: "+value.Issuer, "Account: "+value.AccountName, "Secret: "+core.MaskOTPSecret(value.Secret))
			if codeErr == nil {
				progress := otpProgress(code.RemainingSeconds, code.PeriodSeconds)
				lines = append(lines, "Code: "+code.Value, fmt.Sprintf("Remaining: %ds %s", code.RemainingSeconds, progress))
			} else {
				lines = append(lines, "Code: "+clientapp.UserFacingError(codeErr))
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

func (m model) updateFocusedInput(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.inputs[m.focus], cmd = m.inputs[m.focus].Update(key)
	return m, cmd
}

func makeInputs(labels []string, hidden map[int]bool) []textinput.Model {
	inputs := make([]textinput.Model, 0, len(labels))
	for i, label := range labels {
		input := textinput.New()
		input.Placeholder = label
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

func inputsForKind(kind secretKind) []textinput.Model {
	switch kind {
	case secretKindText:
		return makeInputs([]string{"Title", "Text"}, nil)
	case secretKindLoginPassword:
		return makeInputs([]string{"Title", "Secret login", "Secret password", "URL", "Notes"}, map[int]bool{2: true})
	case secretKindBankCard:
		return makeInputs([]string{"Title", "Card number", "Cardholder name", "Expiration month", "Expiration year", "CVV", "Notes"}, map[int]bool{5: true})
	case secretKindBinary:
		return makeInputs([]string{"Title", "File path", "Content type"}, nil)
	case secretKindOTP:
		inputs := makeInputs([]string{"Title", "Issuer", "Account", "Secret", "Digits", "Period seconds", "Algorithm", "Notes"}, map[int]bool{3: true})
		inputs[4].SetValue("6")
		inputs[5].SetValue(strconv.Itoa(core.DefaultOTPPeriodSeconds))
		inputs[6].SetValue("SHA1")
		return inputs
	default:
		return makeInputs([]string{"Title"}, nil)
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
