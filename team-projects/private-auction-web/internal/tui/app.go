// 블라인드 경매 통합 앱 TUI
// 로그인 역할(ADMIN/AUCTIONEER/BIDDER/GUEST)에 따라 화면 전환
package tui

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"blind-auction-go/internal/auction"
	"blind-auction-go/internal/bid"
	"blind-auction-go/internal/db"
	"blind-auction-go/internal/log"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/auth"
	appErrors "blind-auction-go/pkg/errors"
	"blind-auction-go/pkg/models"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------
//  스타일링
// ---------------------------------------------------------

var (
	focusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle  = focusedStyle
	noStyle      = lipgloss.NewStyle()
	helpStyle    = blurredStyle

	focusedButton = focusedStyle.Render("[ 로그인 ]")
	blurredButton = fmt.Sprintf("[ %s ]", blurredStyle.Render("로그인"))
	focusedSignUp = focusedStyle.Render("[ 회원가입 ]")
	blurredSignUp = fmt.Sprintf("[ %s ]", blurredStyle.Render("회원가입"))

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			MarginBottom(1)

	successStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true).Padding(1)
	errorStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF3340")).Padding(1)
	lockoutStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8C00")).Bold(true).Padding(1)
	guestStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Italic(true)
	adminTitleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#000000")).Background(lipgloss.Color("#FFD700")).Padding(0, 1)
	auctionTitleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#7D56F4")).Padding(0, 1)
	bidderTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#00875A")).Padding(0, 1)
	registerTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#00875A")).Padding(0, 1)
	keyNoticeStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8C00")).Bold(true)
	infoStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB"))
	statusOpenStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	statusClosedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8C00"))
	statusRevStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))
	winnerStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	selectedStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
)

// ---------------------------------------------------------
//  상태 정의
// ---------------------------------------------------------

type sessionState int

const (
	stateInput sessionState = iota
	stateLoggingIn
	stateSuccess
	stateError
	stateSessionExpired
	stateRegister
	stateRegistering
	stateRegisterSuccess

	stateAdminDashboard
	stateAdminUserList
	stateAdminUserLogs
	stateWhitelistList
	stateWhitelistAdd
	stateWhitelistRemove

	stateAuctioneerDashboard
	stateCreateAuction
	stateAuctionList
	stateAuctionActions
	stateAuctionProcessing
	stateAuctionApproval
	stateAuctionResult

	stateKeySetup
	stateBidderDashboard
	stateBidderAuctionList
	stateBidInput
	stateBidSubmitting
	stateBidSuccess
	stateReauth // 중요 작업 전 재인증 상태
)

// ---------------------------------------------------------
//  모델
// ---------------------------------------------------------

type model struct {
	state        sessionState
	focusIndex   int
	inputs       []textinput.Model
	confirmInput textinput.Model
	spinner      spinner.Model
	err          error

	// 인증
	history        *auth.LoginHistory
	token          string
	claims         *auth.UserClaims
	authenticator  auth.Authenticator
	whitelistStore *db.WhitelistStore
	userStore      *db.UserStore
	auditLogger    *security.AuditLogger
	menuCursor     int
	whitelistUsers []models.WhitelistUser
	allUsers       []models.User
	userAuditLogs  []security.AuditLogEntry
	registeredRole models.Role

	auctionService *auction.Service
	auctions       []*models.Auction
	selectedAucIdx int
	auctionResult  *auction.AuctionResult
	processingMsg  string
	approvalTokens []security.ApprovalToken

	// 입찰
	bidService      *bid.Service
	keyPath         string
	newKeyGenerated bool

	// 재인증 (Step-up Auth)
	reauthInput     textinput.Model
	reauthPrevState sessionState
	reauthCallback  func(m model) (tea.Model, tea.Cmd)
}

// ---------------------------------------------------------
//  메시지 타입
// ---------------------------------------------------------

type dbInitMsg struct {
	authInstance   auth.Authenticator
	whitelistStore *db.WhitelistStore
	userStore      *db.UserStore
	auditLogger    *security.AuditLogger
	auctionService *auction.Service
	bidService     *bid.Service
	err            error
}

type loginMsg struct {
	token   string
	claims  *auth.UserClaims
	history *auth.LoginHistory
	err     error
}

type registerMsg struct {
	role models.Role
	err  error
}

type whitelistLoadedMsg struct {
	users []models.WhitelistUser
	err   error
}

type usersLoadedMsg struct {
	users []models.User
	err   error
}

type auditLogsLoadedMsg struct {
	logs []security.AuditLogEntry
	err  error
}

type defaultResultMsg struct{ err error }

type auctionsLoadedMsg struct {
	auctions []*models.Auction
	err      error
}

type auctionOpDoneMsg struct{ err error }

type auctionResultMsg struct {
	result *auction.AuctionResult
	err    error
}

type approvalsLoadedMsg struct {
	tokens []security.ApprovalToken
	err    error
}

type keySetupDoneMsg struct {
	newlyGenerated bool
	keyPath        string
	err            error
}

type bidSubmittedMsg struct{ err error }

// ---------------------------------------------------------
//  초기화
// ---------------------------------------------------------

func initialModel() model {
	m := model{
		state: stateInput,
	}

	m.setupLoginInputs()

	ci := textinput.New()
	ci.Placeholder = "비밀번호 확인"
	ci.EchoMode = textinput.EchoPassword
	ci.EchoCharacter = '*'
	ci.CharLimit = 32
	ci.Cursor.Style = cursorStyle
	m.confirmInput = ci

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	m.spinner = s

	return m
}

func (m *model) setupLoginInputs() {
	m.inputs = make([]textinput.Model, 2)
	for i := range m.inputs {
		t := textinput.New()
		t.Cursor.Style = cursorStyle
		t.CharLimit = 32
		switch i {
		case 0:
			t.Placeholder = "사용자 이름"
			t.Focus()
			t.PromptStyle = focusedStyle
			t.TextStyle = focusedStyle
		case 1:
			t.Placeholder = "비밀번호"
			t.EchoMode = textinput.EchoPassword
			t.EchoCharacter = '*'
		}
		m.inputs[i] = t
	}
	m.focusIndex = 0
}

func (m *model) setupRegisterInputs() {
	m.setupLoginInputs()
	m.state = stateRegister
	m.confirmInput.SetValue("")
}

func (m *model) setupWhitelistAddInputs() {
	m.state = stateWhitelistAdd
	m.inputs = make([]textinput.Model, 2)
	m.inputs[0] = textinput.New()
	m.inputs[0].Placeholder = "사용자 이름"
	m.inputs[0].Focus()
	m.inputs[1] = textinput.New()
	m.inputs[1].Placeholder = "역할 (BIDDER/AUCTIONEER/ADMIN)"
	m.inputs[1].EchoMode = textinput.EchoNormal
	m.focusIndex = 0
}

func (m *model) setupWhitelistRemoveInputs() {
	m.state = stateWhitelistRemove
	m.inputs = make([]textinput.Model, 1)
	m.inputs[0] = textinput.New()
	m.inputs[0].Placeholder = "삭제할 사용자 이름"
	m.inputs[0].Focus()
	m.focusIndex = 0
}

func (m *model) setupBidInput() {
	m.state = stateBidInput
	m.err = nil
	m.inputs = make([]textinput.Model, 1)
	m.inputs[0] = textinput.New()
	m.inputs[0].Placeholder = "입찰가 (숫자, 단위: 원)"
	m.inputs[0].Focus()
	m.inputs[0].PromptStyle = focusedStyle
	m.inputs[0].TextStyle = focusedStyle
	m.focusIndex = 0
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, initDBCommand())
}

// ---------------------------------------------------------
//  커맨드 함수
// ---------------------------------------------------------

func initDBCommand() tea.Cmd {
	return func() tea.Msg {
		dbPath := os.Getenv("DB_PATH")
		if dbPath == "" {
			dbPath = "db/blind_auction.db"
		}
		// 필수 디렉토리 사전 생성 (G301 (CWE-276): 과도한 권한 수정)
		if err := os.MkdirAll("db", 0750); err != nil { // db 디렉토리 권한 0750으로 강화
			return dbInitMsg{err: fmt.Errorf("db 디렉터리 생성 실패: %v", err)}
		}

		// keys 디렉토리 생성 (개인키 저장용, 소유자만 접근 가능)
		if err := os.MkdirAll("keys", 0700); err != nil {
			return dbInitMsg{err: fmt.Errorf("keys 디렉터리 생성 실패: %v", err)}
		}

		conn, err := db.InitDB(dbPath)
		if err != nil {
			return dbInitMsg{err: err}
		}
		userStore := db.NewUserStore(conn)
		sessionStore := db.NewSessionStore(conn)
		whitelistStore := db.NewWhitelistStore(conn)
		authInstance := auth.NewAuthenticator(userStore, sessionStore, whitelistStore)
		auditLogger := security.NewAuditLogger(conn)
		auctionService := auction.NewService(conn, auditLogger)
		bidService := bid.NewService(conn, auditLogger)
		return dbInitMsg{
			authInstance:   authInstance,
			whitelistStore: whitelistStore,
			userStore:      userStore,
			auditLogger:    auditLogger,
			auctionService: auctionService,
			bidService:     bidService,
		}
	}
}

func doLogin(a auth.Authenticator, username, password string) tea.Cmd {
	username = strings.TrimSpace(username)
	return func() tea.Msg {
		token, history, err := a.Login(username, password)
		if err != nil {
			time.Sleep(300 * time.Millisecond)
			return loginMsg{err: err}
		}
		claims, validToken, vErr := a.ValidateToken(token)
		if vErr != nil {
			return loginMsg{err: vErr}
		}
		time.Sleep(300 * time.Millisecond)
		return loginMsg{token: validToken, claims: claims, history: history}
	}
}

func (m *model) setupReauth(callback func(m model) (tea.Model, tea.Cmd)) {
	m.reauthPrevState = m.state
	m.reauthCallback = callback
	m.state = stateReauth
	m.reauthInput = textinput.New()
	m.reauthInput.Placeholder = "비밀번호를 다시 입력하세요"
	m.reauthInput.EchoMode = textinput.EchoPassword
	m.reauthInput.Focus()
	m.err = nil
}

func doReauthenticate(a auth.Authenticator, userID, password string) tea.Cmd {
	return func() tea.Msg {
		err := a.Reauthenticate(userID, password)
		return reauthMsg{err: err}
	}
}

type reauthMsg struct {
	err error
}

func doRegister(userStore *db.UserStore, whitelistStore *db.WhitelistStore, username, password, confirm string) tea.Cmd {
	username = strings.TrimSpace(username)
	return func() tea.Msg {
		if password != confirm {
			return registerMsg{err: fmt.Errorf("비밀번호가 일치하지 않습니다")}
		}
		if err := auth.ValidatePassword(password); err != nil {
			return registerMsg{err: err}
		}
		existing, err := userStore.GetByUsername(username)
		if err != nil {
			return registerMsg{err: fmt.Errorf("내부 오류가 발생했습니다")}
		}
		if existing != nil {
			return registerMsg{err: fmt.Errorf("이미 사용 중인 아이디입니다")}
		}
		initialRole := models.RoleGuest
		wl, _ := whitelistStore.GetByUsername(username)
		if wl != nil {
			initialRole = wl.AssignedRole
		}
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return registerMsg{err: fmt.Errorf("내부 오류가 발생했습니다")}
		}
		hashed := security.HashPassword(password, salt)
		if _, err := userStore.CreateUser(username, hashed, salt, initialRole); err != nil {
			return registerMsg{err: fmt.Errorf("회원가입에 실패했습니다")}
		}
		return registerMsg{role: initialRole}
	}
}

func loadWhitelist(store *db.WhitelistStore) tea.Cmd {
	return func() tea.Msg {
		users, err := store.GetAllWhitelistUsers()
		return whitelistLoadedMsg{users: users, err: err}
	}
}

func loadAllUsers(store *db.UserStore) tea.Cmd {
	return func() tea.Msg {
		users, err := store.GetAllUsers()
		return usersLoadedMsg{users: users, err: err}
	}
}

func banUser(store *db.UserStore, userID string, isBanned bool) tea.Cmd {
	return func() tea.Msg {
		return defaultResultMsg{err: store.SetBanStatus(userID, isBanned)}
	}
}

func loadAuditLogsByUser(logger *security.AuditLogger, adminUser *models.User, targetUserID string) tea.Cmd {
	return func() tea.Msg {
		logs, err := logger.GetAuditLogsByUser(context.Background(), adminUser, targetUserID)
		return auditLogsLoadedMsg{logs: logs, err: err}
	}
}

func addWhitelist(store *db.WhitelistStore, username string, role models.Role) tea.Cmd {
	username = strings.TrimSpace(username)
	return func() tea.Msg {
		return defaultResultMsg{err: store.AddUserToWhitelist(username, role)}
	}
}

func removeWhitelist(store *db.WhitelistStore, username string) tea.Cmd {
	username = strings.TrimSpace(username)
	return func() tea.Msg {
		return defaultResultMsg{err: store.RemoveUserFromWhitelist(username)}
	}
}

func validateSession(a auth.Authenticator, token string) tea.Cmd {
	return func() tea.Msg {
		_, _, err := a.ValidateToken(token)
		if err != nil {
			return loginMsg{err: err}
		}
		return nil
	}
}

// G304(CWE-22) 대응: os.OpenRoot로 파일 접근을 keys/ 디렉토리 내로 제한
func checkOrSetupKey(userID, username string, userStore *db.UserStore) tea.Cmd {
	return func() tea.Msg {
		// filepath.Base로 경로 컴포넌트(../ 등)를 제거하고 파일명만 추출
		keyFileName := filepath.Base(fmt.Sprintf("%s_ed25519.pem", username))

		if err := os.MkdirAll("keys", 0700); err != nil {
			return keySetupDoneMsg{err: toUserFacingError(err, "KEYSETUP_DIR_CREATE_FAIL", "", userID)}
		}

		// os.OpenRoot로 파일 접근 범위를 keys/ 디렉토리로 고정
		root, err := os.OpenRoot("keys")
		if err != nil {
			return keySetupDoneMsg{err: toUserFacingError(err, "KEYSETUP_ROOT_OPEN_FAIL", "", userID)}
		}
		defer root.Close()

		// 파일 존재 여부 확인 (root 범위 내에서)
		_, fileErr := root.Stat(keyFileName)
		fileExists := fileErr == nil

		user, err := userStore.GetByID(userID)
		if err != nil {
			return keySetupDoneMsg{err: toUserFacingError(err, "KEYSETUP_USER_FETCH_FAIL", "", userID)}
		}

		keyPath := fmt.Sprintf("keys/%s", keyFileName)
		if fileExists && user.PublicKey != "" {
			return keySetupDoneMsg{newlyGenerated: false, keyPath: keyPath}
		}

		privPEM, pubPEM, err := security.GenerateEd25519KeyPair()
		if err != nil {
			return keySetupDoneMsg{err: toUserFacingError(err, "KEYSETUP_KEYGEN_FAIL", "", userID)}
		}
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			return keySetupDoneMsg{err: fmt.Errorf("공개키 파싱 실패")}
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return keySetupDoneMsg{err: toUserFacingError(err, "KEYSETUP_PUBKEY_PARSE_FAIL", "", userID)}
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return keySetupDoneMsg{err: fmt.Errorf("Ed25519 키가 아닙니다")}
		}
		if err := userStore.UpdatePublicKey(userID, hex.EncodeToString([]byte(edPub))); err != nil {
			return keySetupDoneMsg{err: toUserFacingError(err, "KEYSETUP_PUBKEY_SAVE_FAIL", "", userID)}
		}
		// root.WriteFile로 keys/ 범위 내에서만 기록 (디렉토리 트래버설 차단)
		if err := root.WriteFile(keyFileName, []byte(privPEM), 0600); err != nil {
			return keySetupDoneMsg{err: toUserFacingError(err, "KEYSETUP_PRIVKEY_SAVE_FAIL", "", userID)}
		}
		return keySetupDoneMsg{newlyGenerated: true, keyPath: keyPath}
	}
}

func loadAuctions(svc *auction.Service) tea.Cmd {
	return func() tea.Msg {
		auctions, err := svc.ListAuctions()
		return auctionsLoadedMsg{auctions: auctions, err: err}
	}
}

func doCloseAuction(svc *auction.Service, id string) tea.Cmd {
	return func() tea.Msg {
		return auctionOpDoneMsg{err: svc.CloseAuction(context.Background(), id)}
	}
}

func doRevealAuction(svc *auction.Service, id string) tea.Cmd {
	return func() tea.Msg {
		return auctionOpDoneMsg{err: svc.RevealAuctionResults(context.Background(), id)}
	}
}

func doLoadResult(svc *auction.Service, id string) tea.Cmd {
	return func() tea.Msg {
		result, err := svc.GetAuctionResult(id)
		return auctionResultMsg{result: result, err: err}
	}
}

func loadApprovals(svc *auction.Service, id string) tea.Cmd {
	return func() tea.Msg {
		tokens, err := svc.GetApprovalTokens(id)
		return approvalsLoadedMsg{tokens: tokens, err: err}
	}
}

func doApproveAuction(svc *auction.Service, auctionID, adminID string, adminPriv ed25519.PrivateKey) tea.Cmd {
	return func() tea.Msg {
		now := time.Now().UTC()
		payload := fmt.Sprintf("APPROVE:%s:%s", auctionID, now.Format(time.RFC3339))
		sig := security.SignMessage(adminPriv, []byte(payload))
		err := svc.AddApprovalToken(auctionID, adminID, sig, now)
		return auctionOpDoneMsg{err: err}
	}
}

func doSubmitBid(
	bidSvc *bid.Service,
	auctionSvc *auction.Service,
	userID, auctionID string,
	price int,
	keyPath string,
) tea.Cmd {
	return func() tea.Msg {
		auc, err := auctionSvc.GetAuction(auctionID)
		if err != nil {
			return bidSubmittedMsg{err: toUserFacingError(err, "BID_AUCTION_FETCH_FAIL", auctionID, userID)}
		}
		dek := make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return bidSubmittedMsg{err: toUserFacingError(err, "BID_DEK_GEN_FAIL", auctionID, userID)}
		}
		nonceBytes := make([]byte, 12)
		if _, err := rand.Read(nonceBytes); err != nil {
			return bidSubmittedMsg{err: toUserFacingError(err, "BID_NONCE_GEN_FAIL", auctionID, userID)}
		}
		nonceStr := base64.StdEncoding.EncodeToString(nonceBytes)

		priceData := []byte(strconv.Itoa(price))
		block, _ := aes.NewCipher(dek)
		aesGcm, _ := cipher.NewGCM(block)
		ciphertextBid := aesGcm.Seal(nil, nonceBytes, priceData, nil)

		encryptedDEK, err := security.EncryptRSA(auc.PublicKey, dek)
		if err != nil {
			return bidSubmittedMsg{err: toUserFacingError(err, "BID_ENCRYPT_FAIL", auctionID, userID)}
		}

		commitHash := security.GenerateCommitment(price, nonceStr, userID)

		// Ed25519 서명 — os.OpenRoot로 keys/ 범위 내에서만 읽기 (G304/CWE-22 방지)
		root, err := os.OpenRoot("keys")
		if err != nil {
			return bidSubmittedMsg{err: toUserFacingError(err, "BID_ROOT_OPEN_FAIL", auctionID, userID)}
		}
		defer root.Close()
		privPEMBytes, err := root.ReadFile(filepath.Base(keyPath))
		if err != nil {
			return bidSubmittedMsg{err: toUserFacingError(err, "BID_KEY_READ_FAIL", auctionID, userID)}
		}
		privKey, err := security.LoadEd25519PrivateKey(string(privPEMBytes))
		if err != nil {
			return bidSubmittedMsg{err: toUserFacingError(err, "BID_KEY_PARSE_FAIL", auctionID, userID)}
		}
		defer security.ZeroingMemory(privKey)

		signedPayload := fmt.Sprintf("%s:%x:%x:%s", auc.ID, encryptedDEK, ciphertextBid, commitHash)
		signature := security.SignMessage(privKey, []byte(signedPayload))
		if _, err := bidSvc.SubmitBid(userID, auc.ID, encryptedDEK, ciphertextBid, nonceStr, commitHash, signature); err != nil {
			return bidSubmittedMsg{err: toUserFacingError(err, "BID_SUBMIT_FAIL", auc.ID, userID)}
		}
		return bidSubmittedMsg{}
	}
}

func toUserFacingError(err error, event, auctionID, userID string) error {
	if err == nil {
		return nil
	}
	var appErr *appErrors.AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	log.Error(event, auctionID, userID, "", err.Error(), appErrors.ErrSystemError.Code)
	return appErrors.ErrSystemError
}

func formatErrorForUI(err error) string {
	if err == nil {
		return ""
	}
	var appErr *appErrors.AppError
	if errors.As(err, &appErr) {
		return appErr.Message
	}
	return err.Error()
}

// ---------------------------------------------------------
//  업데이트 함수
// ---------------------------------------------------------

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	// 키 입력 처리
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit

		case "esc":
			switch m.state {
			case stateRegister, stateRegisterSuccess:
				return m.resetToLogin()
			case stateWhitelistList, stateWhitelistAdd, stateWhitelistRemove:
				m.state = stateAdminDashboard
				return m, nil
			case stateAdminUserList:
				m.state = stateAdminDashboard
				m.menuCursor = 0
				return m, nil
			case stateAdminUserLogs:
				m.state = stateAdminUserList
				return m, nil
			case stateAuctioneerDashboard:
				if m.claims != nil && m.claims.Role == models.RoleAdmin {
					m.state = stateAdminDashboard
				} else {
					return m.doLogout()
				}
				return m, nil
			case stateCreateAuction:
				m.state = stateAuctioneerDashboard
				return m, nil
			case stateAuctionList:
				m.state = stateAuctioneerDashboard
				return m, nil
			case stateAuctionActions:
				m.state = stateAuctionList
				m.menuCursor = 0
				return m, nil
			case stateAuctionResult:
				m.state = stateAuctionActions
				m.menuCursor = 0
				return m, nil
			case stateBidderDashboard:
				return m.doLogout()
			case stateBidderAuctionList:
				m.state = stateBidderDashboard
				return m, nil
			case stateBidInput:
				m.state = stateBidderAuctionList
				return m, nil
			case stateBidSuccess:
				m.state = stateBidderAuctionList
				return m, loadAuctions(m.auctionService)
			case stateAdminDashboard, stateSessionExpired, stateSuccess:
				return m.doLogout()
			default:
				return m, tea.Quit
			}
		}

		// 상태별 처리
		switch m.state {

		// 로그인
		case stateInput, stateError:
			s := msg.String()
			if s == "tab" || s == "shift+tab" || s == "enter" || s == "up" || s == "down" {
				if s == "enter" && m.focusIndex == len(m.inputs) {
					if m.authenticator == nil {
						m.err = fmt.Errorf("DB 초기화 중입니다. 잠시 후 다시 시도하세요")
						m.state = stateError
						return m, nil
					}
					m.err = nil
					m.state = stateLoggingIn
					return m, tea.Batch(m.spinner.Tick, doLogin(m.authenticator, m.inputs[0].Value(), m.inputs[1].Value()))
				}
				// 회원가입 버튼
				if s == "enter" && m.focusIndex == len(m.inputs)+1 {
					m.err = nil
					m.setupRegisterInputs()
					return m, m.inputs[0].Focus()
				}
				if s == "up" || s == "shift+tab" {
					m.focusIndex--
				} else {
					m.focusIndex++
				}
				if m.focusIndex > len(m.inputs)+1 {
					m.focusIndex = 0
				} else if m.focusIndex < 0 {
					m.focusIndex = len(m.inputs) + 1
				}
				cmds := make([]tea.Cmd, len(m.inputs))
				for i := range m.inputs {
					if i == m.focusIndex {
						cmds[i] = m.inputs[i].Focus()
						m.inputs[i].PromptStyle = focusedStyle
						m.inputs[i].TextStyle = focusedStyle
					} else {
						m.inputs[i].Blur()
						m.inputs[i].PromptStyle = noStyle
						m.inputs[i].TextStyle = noStyle
					}
				}
				return m, tea.Batch(cmds...)
			}

		// 회원가입
		case stateRegister:
			s := msg.String()
			if s == "tab" || s == "shift+tab" || s == "enter" || s == "up" || s == "down" {
				if s == "enter" && m.focusIndex == 3 {
					if m.userStore == nil {
						m.err = fmt.Errorf("DB 초기화 중입니다")
						return m, nil
					}
					m.state = stateRegistering
					return m, tea.Batch(m.spinner.Tick, doRegister(m.userStore, m.whitelistStore, m.inputs[0].Value(), m.inputs[1].Value(), m.confirmInput.Value()))
				}
				if s == "up" || s == "shift+tab" {
					m.focusIndex--
				} else {
					m.focusIndex++
				}
				if m.focusIndex > 3 {
					m.focusIndex = 0
				} else if m.focusIndex < 0 {
					m.focusIndex = 3
				}
				cmds := make([]tea.Cmd, 3)
				for i := 0; i < 2; i++ {
					if i == m.focusIndex {
						cmds[i] = m.inputs[i].Focus()
						m.inputs[i].PromptStyle = focusedStyle
						m.inputs[i].TextStyle = focusedStyle
					} else {
						m.inputs[i].Blur()
						m.inputs[i].PromptStyle = noStyle
						m.inputs[i].TextStyle = noStyle
					}
				}
				if m.focusIndex == 2 {
					cmds[2] = m.confirmInput.Focus()
					m.confirmInput.PromptStyle = focusedStyle
				} else {
					m.confirmInput.Blur()
					m.confirmInput.PromptStyle = noStyle
				}
				return m, tea.Batch(cmds...)
			}

		// 관리자 대시보드
		case stateAdminDashboard:
			switch msg.String() {
			case "up", "k":
				if m.menuCursor > 0 {
					m.menuCursor--
				}
			case "down", "j":
				if m.menuCursor < 5 {
					m.menuCursor++
				}
			case "enter":
				switch m.menuCursor {
				case 0: // 사용자 관리 및 로그
					m.state = stateAdminUserList
					m.menuCursor = 0
					return m, loadAllUsers(m.userStore)
				case 1:
					m.state = stateWhitelistList
					return m, loadWhitelist(m.whitelistStore)
				case 2:
					m.setupWhitelistAddInputs()
				case 3:
					m.setupWhitelistRemoveInputs()
				case 4: // 경매 관리
					m.state = stateAuctioneerDashboard
					m.menuCursor = 0
				case 5: // 로그아웃
					return m.doLogout()
				}
			}

		case stateAdminUserList:
			switch msg.String() {
			case "up", "k":
				if m.menuCursor > 0 {
					m.menuCursor--
				}
			case "down", "j":
				if m.menuCursor < len(m.allUsers)-1 {
					m.menuCursor++
				}
			case "esc":
				m.state = stateAdminDashboard
				m.menuCursor = 0
				return m, nil
			case "l": // 로그 보기
				if len(m.allUsers) > 0 {
					target := m.allUsers[m.menuCursor]
					// ADMIN 권한을 가진 User 모델이 필요함 (현재는 claims만 있음)
					// UserStore에서 admin 정보를 가져와야 함. 
					// 간단히 하기 위해 AuditLogger.GetAuditLogsByUser를 admin 체크 없이 쓰거나,
					// Authenticator에 위임하는 것이 좋음.
					// 여기서는 m.claims를 models.User로 변환하여 전달 (실제 필드는 claims와 매칭됨)
					admin := &models.User{ID: m.claims.UserID, Username: m.claims.Username, Role: m.claims.Role}
					m.state = stateAdminUserLogs
					return m, tea.Batch(m.spinner.Tick, loadAuditLogsByUser(m.auditLogger, admin, target.ID))
				}
			case "b": // 밴/해제
				if len(m.allUsers) > 0 {
					target := m.allUsers[m.menuCursor]
					m.setupReauth(func(m model) (tea.Model, tea.Cmd) {
						return m, banUser(m.userStore, target.ID, !target.IsBanned)
					})
				}
			case "r": // 새로고침
				return m, loadAllUsers(m.userStore)
			}

		case stateAdminUserLogs:
			if msg.String() == "esc" {
				m.state = stateAdminUserList
				return m, nil
			}

		// 화이트리스트 추가/삭제
		case stateWhitelistAdd, stateWhitelistRemove:
			s := msg.String()
			limit := 1
			if m.state == stateWhitelistAdd {
				limit = 2
			}
			if s == "tab" || s == "shift+tab" || s == "enter" || s == "up" || s == "down" {
				if s == "enter" && m.focusIndex == limit {
					if m.state == stateWhitelistAdd {
						role := models.Role(strings.TrimSpace(m.inputs[1].Value()))
						return m, tea.Batch(validateSession(m.authenticator, m.token), addWhitelist(m.whitelistStore, m.inputs[0].Value(), role))
					}
					return m, tea.Batch(validateSession(m.authenticator, m.token), removeWhitelist(m.whitelistStore, m.inputs[0].Value()))
				}
				if s == "up" || s == "shift+tab" {
					m.focusIndex--
				} else {
					m.focusIndex++
				}
				if m.focusIndex > limit {
					m.focusIndex = 0
				} else if m.focusIndex < 0 {
					m.focusIndex = limit
				}
				cmds := make([]tea.Cmd, 2)
				for i := 0; i < limit; i++ {
					if i == m.focusIndex {
						cmds[i] = m.inputs[i].Focus()
						m.inputs[i].PromptStyle = focusedStyle
						m.inputs[i].TextStyle = focusedStyle
					} else {
						m.inputs[i].Blur()
						m.inputs[i].PromptStyle = noStyle
						m.inputs[i].TextStyle = noStyle
					}
				}
				return m, tea.Batch(cmds...)
			}

		case stateReauth:
			if msg.String() == "enter" {
				return m, doReauthenticate(m.authenticator, m.claims.UserID, m.reauthInput.Value())
			}
			if msg.String() == "esc" {
				m.state = m.reauthPrevState
				return m, nil
			}
			var cmd tea.Cmd
			m.reauthInput, cmd = m.reauthInput.Update(msg)
			return m, cmd

		// 경매 관리 대시보드
		case stateAuctioneerDashboard:
			switch msg.String() {
			case "up", "k":
				if m.menuCursor > 0 {
					m.menuCursor--
				}
			case "down", "j":
				maxIdx := 1
				if m.claims != nil && m.claims.Role == models.RoleAdmin {
					maxIdx = 2 // 뒤로가기 항목 포함
				}
				if m.menuCursor < maxIdx {
					m.menuCursor++
				}
			case "enter":
				switch m.menuCursor {
				case 0:
					m.setupCreateAuctionInputs()
				case 1:
					m.state = stateAuctionList
					m.selectedAucIdx = 0
					return m, loadAuctions(m.auctionService)
				case 2:
					if m.claims != nil && m.claims.Role == models.RoleAdmin {
						m.state = stateAdminDashboard
						m.menuCursor = 0
					} else {
						return m.doLogout()
					}
				}
			}

		// 경매 생성
		case stateCreateAuction:
			s := msg.String()
			if s == "tab" || s == "shift+tab" || s == "enter" || s == "up" || s == "down" {
				if s == "enter" && m.focusIndex == len(m.inputs) {
					m.setupReauth(func(m model) (tea.Model, tea.Cmd) {
						return m.submitCreateAuction()
					})
					return m, nil
				}
				if s == "up" || s == "shift+tab" {
					m.focusIndex--
				} else {
					m.focusIndex++
				}
				if m.focusIndex > len(m.inputs) {
					m.focusIndex = 0
				} else if m.focusIndex < 0 {
					m.focusIndex = len(m.inputs)
				}
				cmds := make([]tea.Cmd, len(m.inputs))
				for i := range m.inputs {
					if i == m.focusIndex {
						cmds[i] = m.inputs[i].Focus()
					} else {
						m.inputs[i].Blur()
					}
				}
				return m, tea.Batch(cmds...)
			}

		// 경매 목록
		case stateAuctionList:
			switch msg.String() {
			case "up", "k":
				if m.selectedAucIdx > 0 {
					m.selectedAucIdx--
				}
			case "down", "j":
				if m.selectedAucIdx < len(m.auctions)-1 {
					m.selectedAucIdx++
				}
			case "r":
				return m, loadAuctions(m.auctionService)
			case "enter":
				if len(m.auctions) > 0 {
					m.state = stateAuctionActions
					m.menuCursor = 0
				}
			}

		// 경매 액션
		case stateAuctionActions:
			auc := m.auctions[m.selectedAucIdx]
			switch msg.String() {
			case "up", "k":
				if m.menuCursor > 0 {
					m.menuCursor--
				}
			case "down", "j":
				if m.menuCursor < 1 {
					m.menuCursor++
				}
			case "enter":
				if m.menuCursor == 2 || (auc.Status != "CLOSED" && m.menuCursor == 1) {
					m.state = stateAuctionList
					m.menuCursor = 0
					return m, nil
				}
				switch auc.Status {
				case "OPEN":
					m.setupReauth(func(m model) (tea.Model, tea.Cmd) {
						m.state = stateAuctionProcessing
						m.processingMsg = fmt.Sprintf("'%s' 경매 마감 중...", security.SanitizeTUI(auc.Title))
						return m, tea.Batch(m.spinner.Tick, doCloseAuction(m.auctionService, auc.ID))
					})
					return m, nil
				case "CLOSED":
					if m.menuCursor == 0 {
						// 승인 현황 보기 및 승인하기
						m.state = stateAuctionProcessing
						m.processingMsg = "승인 현황 확인 중..."
						return m, tea.Batch(m.spinner.Tick, loadApprovals(m.auctionService, auc.ID))
					} else {
						// 결과 공개 시도
						m.setupReauth(func(m model) (tea.Model, tea.Cmd) {
							m.state = stateAuctionProcessing
							m.processingMsg = fmt.Sprintf("'%s' 결과 공개 중...", security.SanitizeTUI(auc.Title))
							return m, tea.Batch(m.spinner.Tick, doRevealAuction(m.auctionService, auc.ID))
						})
						return m, nil
					}
				case "REVEALED":
					m.state = stateAuctionProcessing
					m.processingMsg = "결과 불러오는 중..."
					return m, tea.Batch(m.spinner.Tick, doLoadResult(m.auctionService, auc.ID))
				}
			}

		// 입찰자 대시보드
		case stateBidderDashboard:
			switch msg.String() {
			case "up", "k":
				if m.menuCursor > 0 {
					m.menuCursor--
				}
			case "down", "j":
				if m.menuCursor < 1 {
					m.menuCursor++
				}
			case "enter":
				switch m.menuCursor {
				case 0:
					m.state = stateBidderAuctionList
					m.selectedAucIdx = 0
					return m, loadAuctions(m.auctionService)
				case 1:
					return m.doLogout()
				}
			}

		// 입찰자 경매 목록
		case stateBidderAuctionList:
			switch msg.String() {
			case "up", "k":
				if m.selectedAucIdx > 0 {
					m.selectedAucIdx--
				}
			case "down", "j":
				if m.selectedAucIdx < len(m.auctions)-1 {
					m.selectedAucIdx++
				}
			case "r":
				return m, loadAuctions(m.auctionService)
			case "enter":
				if len(m.auctions) == 0 {
					return m, nil
				}
				auc := m.auctions[m.selectedAucIdx]
				switch auc.Status {
				case "OPEN":
					m.setupBidInput()
				case "REVEALED":
					m.state = stateAuctionProcessing
					m.processingMsg = "결과 불러오는 중..."
					return m, tea.Batch(m.spinner.Tick, doLoadResult(m.auctionService, auc.ID))
				default:
					m.err = fmt.Errorf("%s 상태의 경매는 입찰/조회가 불가합니다", auc.Status)
					// m.state = stateError 삭제하여 목록 유지
					return m, nil
				}
			}

		// 입찰가 입력
		case stateBidInput:
			s := msg.String()
			if s == "tab" || s == "shift+tab" || s == "enter" || s == "up" || s == "down" {
				if s == "enter" && m.focusIndex == len(m.inputs) {
					priceStr := strings.TrimSpace(m.inputs[0].Value())
					price, err := strconv.Atoi(priceStr)
					if err != nil || price <= 0 {
						if err != nil && strings.Contains(err.Error(), "out of range") {
							m.err = fmt.Errorf("입찰가가 너무 큽니다 (최대 허용 범위를 초과하였습니다)")
						} else {
							m.err = fmt.Errorf("입찰가는 0보다 큰 숫자여야 합니다")
						}
						return m, nil
					}
					auc := m.auctions[m.selectedAucIdx]

					// 중요 작업(입찰 제출) 전 재인증 수행
					m.setupReauth(func(m model) (tea.Model, tea.Cmd) {
						m.state = stateBidSubmitting
						m.processingMsg = "입찰 제출 중..."
						return m, tea.Batch(
							m.spinner.Tick,
							doSubmitBid(m.bidService, m.auctionService, m.claims.UserID, auc.ID, price, m.keyPath),
						)
					})
					return m, nil
				}
				if s == "up" || s == "shift+tab" {
					m.focusIndex--
				} else {
					m.focusIndex++
				}
				if m.focusIndex > len(m.inputs) {
					m.focusIndex = 0
				} else if m.focusIndex < 0 {
					m.focusIndex = len(m.inputs)
				}
				cmds := make([]tea.Cmd, len(m.inputs))
				for i := range m.inputs {
					if i == m.focusIndex {
						cmds[i] = m.inputs[i].Focus()
					} else {
						m.inputs[i].Blur()
					}
				}
				return m, tea.Batch(cmds...)
			}

		// 입찰 완료 / 결과 조회
		case stateBidSuccess, stateAuctionResult:
			// 아무 키나 눌러 이전 화면으로
			if m.state == stateBidSuccess {
				m.state = stateBidderAuctionList
				return m, loadAuctions(m.auctionService)
			}
			// stateAuctionResult
			if m.claims != nil && m.claims.Role == models.RoleBidder {
				m.state = stateBidderAuctionList
			} else {
				m.state = stateAuctionActions
				m.menuCursor = 0
			}
			return m, nil

		// 경매 승인 화면
		case stateAuctionApproval:
			switch msg.String() {
			case "enter":
				// 현재 로그인한 관리자의 서명 수행
				auc := m.auctions[m.selectedAucIdx]
				m.setupReauth(func(m model) (tea.Model, tea.Cmd) {
					// 관리자 개인키 로드
					keyFileName := filepath.Base(fmt.Sprintf("%s_ed25519.pem", m.claims.Username))
					root, err := os.OpenRoot("keys")
					if err != nil {
						m.err = err
						m.state = stateError
						return m, nil
					}
					defer root.Close()
					privPEM, err := root.ReadFile(keyFileName)
					if err != nil {
						m.err = fmt.Errorf("개인키를 찾을 수 없습니다. 입찰자 메뉴에서 키를 먼저 생성하세요")
						m.state = stateError
						return m, nil
					}
					privKey, err := security.LoadEd25519PrivateKey(string(privPEM))
					if err != nil {
						m.err = err
						m.state = stateError
						return m, nil
					}
					return m, tea.Batch(m.spinner.Tick, doApproveAuction(m.auctionService, auc.ID, m.claims.UserID, privKey))
				})
			case "esc":
				m.state = stateAuctionActions
				m.menuCursor = 0
				return m, nil
			}
		}

	// 메시지 처리
	case dbInitMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
		} else {
			m.authenticator = msg.authInstance
			m.whitelistStore = msg.whitelistStore
			m.userStore = msg.userStore
			m.auditLogger = msg.auditLogger
			m.auctionService = msg.auctionService
			m.bidService = msg.bidService
		}
		return m, nil

	case createAuctionMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateCreateAuction
			return m, nil
		}
		m.state = stateAuctioneerDashboard
		m.menuCursor = 0
		return m, loadAuctions(m.auctionService)

	case reauthMsg:
		if msg.err != nil {
			m.err = msg.err
			m.reauthInput.SetValue("")
			return m, nil
		}
		// 재인증 성공 시 시각적 피드백 제공 후 작업 실행
		m.err = nil
		m.processingMsg = "인증 성공! 작업을 진행합니다..."
		if m.reauthCallback != nil {
			// 즉시 실행 대신 Batch로 묶어 화면 갱신 유도
			cbModel, cbCmd := m.reauthCallback(m)
			return cbModel, tea.Batch(m.spinner.Tick, cbCmd)
		}
		m.state = m.reauthPrevState
		return m, nil

	case loginMsg:
		if msg.err != nil {
			switch msg.err {
			case auth.ErrAccountLocked:
				m.err = msg.err
				m.state = stateError
			case auth.ErrExpiredToken:
				m.state = stateSessionExpired
			default:
				m.err = msg.err
				m.state = stateError
			}
			return m, nil
		}
		m.token = msg.token
		m.claims = msg.claims
		m.history = msg.history
		m.menuCursor = 0

		switch m.claims.Role {
		case models.RoleAdmin:
			// 관리자도 승인을 위해 서명 키가 필요함
			m.state = stateKeySetup
			return m, tea.Batch(m.spinner.Tick, checkOrSetupKey(m.claims.UserID, m.claims.Username, m.userStore))
		case models.RoleAuctioneer:
			// 경매진행자도 승인을 위해 서명 키가 필요함
			m.state = stateKeySetup
			return m, tea.Batch(m.spinner.Tick, checkOrSetupKey(m.claims.UserID, m.claims.Username, m.userStore))
		case models.RoleBidder:
			// 서명 키 확인 후 입찰자 대시보드로
			m.state = stateKeySetup
			return m, tea.Batch(m.spinner.Tick, checkOrSetupKey(m.claims.UserID, m.claims.Username, m.userStore))
		default: // GUEST
			m.state = stateSuccess
		}
		return m, nil

	case registerMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateRegister
			return m, nil
		}
		m.registeredRole = msg.role
		m.state = stateRegisterSuccess
		m.err = nil
		return m, nil

	case whitelistLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.whitelistUsers = msg.users
		return m, nil

	case usersLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.allUsers = msg.users
		return m, nil

	case auditLogsLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.userAuditLogs = msg.logs
		return m, nil

	case defaultResultMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.state = stateAdminDashboard
		return m, nil

	case keySetupDoneMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.keyPath = msg.keyPath
		m.newKeyGenerated = msg.newlyGenerated
		if m.claims.Role == models.RoleAdmin {
			m.state = stateAdminDashboard
		} else if m.claims.Role == models.RoleAuctioneer {
			m.state = stateAuctioneerDashboard
		} else {
			m.state = stateBidderDashboard
		}
		m.menuCursor = 0
		return m, nil

	case auctionsLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.auctions = msg.auctions
		return m, nil

	case auctionOpDoneMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.state = stateAuctionList
		return m, loadAuctions(m.auctionService)

	case auctionResultMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.auctionResult = msg.result
		m.state = stateAuctionResult
		return m, nil

	case approvalsLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.approvalTokens = msg.tokens
		m.state = stateAuctionApproval
		return m, nil

	case bidSubmittedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.state = stateError
			return m, nil
		}
		m.state = stateBidSuccess
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	// 텍스트 입력 업데이트
	switch m.state {
	case stateInput, stateError, stateWhitelistAdd, stateWhitelistRemove:
		cmds := make([]tea.Cmd, len(m.inputs))
		for i := range m.inputs {
			m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
		}
		return m, tea.Batch(cmds...)
	case stateRegister:
		cmds := make([]tea.Cmd, len(m.inputs))
		for i := range m.inputs {
			m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
		}
		var cc tea.Cmd
		m.confirmInput, cc = m.confirmInput.Update(msg)
		return m, tea.Batch(append(cmds, cc)...)
	case stateCreateAuction, stateBidInput:
		cmds := make([]tea.Cmd, len(m.inputs))
		for i := range m.inputs {
			m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
		}
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

// ---------------------------------------------------------
//  뷰 함수
// ---------------------------------------------------------

func (m model) View() string {
	var s string

	// 1. 현재 상태 또는 재인증 중인 경우 이전 상태에 따른 타이틀 결정
	displayState := m.state
	if m.state == stateReauth {
		displayState = m.reauthPrevState
	}

	// 타이틀 배너
	switch displayState {
	case stateAdminDashboard, stateWhitelistList, stateWhitelistAdd, stateWhitelistRemove:
		s += adminTitleStyle.Render(" BLIND AUCTION - ADMIN ") + "\n\n"
	case stateAuctioneerDashboard, stateCreateAuction, stateAuctionList, stateAuctionActions, stateAuctionProcessing, stateAuctionResult:
		s += auctionTitleStyle.Render(" BLIND AUCTION - 경매 관리 ") + "\n\n"
	case stateKeySetup, stateBidderDashboard, stateBidderAuctionList, stateBidInput, stateBidSubmitting, stateBidSuccess:
		s += bidderTitleStyle.Render(" BLIND AUCTION - 입찰자 ") + "\n\n"
	case stateRegister, stateRegistering, stateRegisterSuccess:
		s += registerTitleStyle.Render(" BLIND AUCTION - 회원가입 ") + "\n\n"
	default:
		s += titleStyle.Render(" BLIND AUCTION - 로그인 ") + "\n\n"
	}

	switch m.state {

	// 로그인 화면
	case stateInput, stateError:
		if m.state == stateError && m.err != nil {
			if m.err == auth.ErrAccountLocked {
				s += lockoutStyle.Render("!! "+formatErrorForUI(m.err)) + "\n\n"
			} else {
				s += errorStyle.Render("!! "+formatErrorForUI(m.err)) + "\n\n"
			}
		}

		// 로그인 화면인 경우에만 입력 필드 표시
		if len(m.inputs) >= 2 {
			s += m.inputs[0].View() + "\n"
			s += m.inputs[1].View() + "\n\n"
			if m.focusIndex == len(m.inputs) {
				s += focusedButton
			} else {
				s += blurredButton
			}
			if m.focusIndex == len(m.inputs)+1 {
				s += "  " + focusedSignUp
			} else {
				s += "  " + blurredSignUp
			}
			s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 | Enter: 확인 | Ctrl+C: 종료")
		} else {
			// 로그인 화면이 아닌 곳에서 발생한 에러 처리
			s += helpStyle.Render("Esc: 뒤로 가기 | Ctrl+C: 종료")
		}

	// 로그인 처리 중
	case stateLoggingIn:
		s += fmt.Sprintf("\n  %s 인증 중...\n", m.spinner.View())

	// GUEST 로그인 성공
	case stateSuccess:
		s += successStyle.Render("!! 로그인 성공") + "\n\n"
		s += fmt.Sprintf("안녕하세요 %s님!\n", security.SanitizeTUI(m.claims.Username))
		s += fmt.Sprintf("역할: %s\n", m.claims.Role)
		s += guestStyle.Render("\n(GUEST 권한입니다. 관리자에게 화이트리스트 등록을 요청하세요)") + "\n"
		s += "\n" + helpStyle.Render("Esc: 로그아웃")

	// 세션 만료
	case stateSessionExpired:
		s += lockoutStyle.Render("!! 세션이 만료되었습니다.") + "\n\n"
		s += helpStyle.Render("Esc: 로그아웃")

	// 회원가입
	case stateRegister:
		if m.err != nil {
			s += errorStyle.Render("!! "+formatErrorForUI(m.err)) + "\n\n"
		} else {
			s += helpStyle.Render("화이트리스트 등록 여부에 따라 초기 권한이 결정됩니다.") + "\n\n"
		}
		s += m.inputs[0].View() + "\n"
		s += m.inputs[1].View() + "\n"
		s += m.confirmInput.View() + "\n\n"
		if m.focusIndex == 3 {
			s += focusedStyle.Render("[ 계정 생성 ]")
		} else {
			s += fmt.Sprintf("[ %s ]", blurredStyle.Render("계정 생성"))
		}
		s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 | Enter: 제출 | Esc: 뒤로")

	case stateRegistering:
		s += fmt.Sprintf("\n  %s 계정 생성 중...\n", m.spinner.View())

	case stateRegisterSuccess:
		s += successStyle.Render("!! 회원가입 완료!") + "\n\n"
		s += fmt.Sprintf("부여된 역할: %s\n\n", security.SanitizeTUI(string(m.registeredRole)))
		if m.registeredRole == models.RoleGuest {
			s += guestStyle.Render("관리자에게 화이트리스트 등록을 요청하면\n입찰(BIDDER) 또는 경매진행(AUCTIONEER) 권한을 받을 수 있습니다.") + "\n"
		} else {
			s += successStyle.Render("사전 등록된 권한으로 즉시 이용 가능합니다.") + "\n"
		}
		s += "\n" + helpStyle.Render("Esc: 로그인 화면으로")

	// 관리자 대시보드
	case stateAdminDashboard:
		s += fmt.Sprintf("환영합니다 %s (ADMIN)\n\n", security.SanitizeTUI(m.claims.Username))
		menus := []string{
			"사용자 관리 및 보안 로그",
			"화이트리스트 조회",
			"화이트리스트 추가",
			"화이트리스트 삭제",
			"경매 관리",
			"로그아웃",
		}
		for i, choice := range menus {
			if m.menuCursor == i {
				s += focusedStyle.Render(fmt.Sprintf("> %s", choice)) + "\n"
			} else {
				s += fmt.Sprintf("  %s\n", choice)
			}
		}
		s += "\n" + helpStyle.Render("j/k 또는 화살표: 이동 | Enter: 선택 | Esc: 로그아웃")

	case stateAdminUserList:
		s += infoStyle.Render("사용자 관리 및 이상 행위 모니터링") + "\n"
		s += helpStyle.Render("L: 보안 로그 조회 | B: 차단/해제 | R: 새로고침") + "\n\n"
		if len(m.allUsers) == 0 {
			s += "가입된 사용자가 없습니다.\n"
		}
		for i, u := range m.allUsers {
			status := ""
			if u.IsBanned {
				status = errorStyle.Render("[BANNED]")
			}
			suspicious := ""
			if u.FailedAttempts >= 3 {
				suspicious = lockoutStyle.Render(fmt.Sprintf("(실패:%d)", u.FailedAttempts))
			}
			line := fmt.Sprintf("%-15s [%-10s] %s %s", security.SanitizeTUI(u.Username), u.Role, status, suspicious)
			if i == m.menuCursor {
				s += selectedStyle.Render("> "+line) + "\n"
			} else {
				s += "  " + line + "\n"
			}
		}
		s += "\n" + helpStyle.Render("Esc: 뒤로")

	case stateAdminUserLogs:
		if len(m.allUsers) > 0 && m.menuCursor < len(m.allUsers) {
			target := m.allUsers[m.menuCursor]
			s += infoStyle.Render(fmt.Sprintf("보안 로그: %s", security.SanitizeTUI(target.Username))) + "\n\n"
			if len(m.userAuditLogs) == 0 {
				s += helpStyle.Render("기록된 보안 이벤트가 없습니다.") + "\n"
			}
			for _, l := range m.userAuditLogs {
				s += fmt.Sprintf("[%s] %-20s %s\n", l.CreatedAt, l.EventType, l.Message)
			}
		} else {
			s += errorStyle.Render("사용자 정보를 불러올 수 없습니다.")
		}
		s += "\n" + helpStyle.Render("Esc: 뒤로")

	// 화이트리스트 조회
	case stateWhitelistList:
		s += "--- 화이트리스트 사용자 ---\n"
		if len(m.whitelistUsers) == 0 {
			s += "등록된 사용자가 없습니다.\n"
		}
		for _, u := range m.whitelistUsers {
			s += fmt.Sprintf("> %s [%s] (등록: %s)\n", security.SanitizeTUI(u.Username), u.AssignedRole, u.CreatedAt.Format("2006-01-02"))
		}
		s += "\n" + helpStyle.Render("Esc: 뒤로")

	// 화이트리스트 추가
	case stateWhitelistAdd:
		s += "화이트리스트에 사용자 추가:\n\n"
		s += m.inputs[0].View() + "\n"
		s += m.inputs[1].View() + "\n\n"
		if m.focusIndex == 2 {
			s += focusedStyle.Render("[ 추가 ]")
		} else {
			s += fmt.Sprintf("[ %s ]", blurredStyle.Render("추가"))
		}
		s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 | Enter: 제출 | Esc: 취소")

	// 화이트리스트 삭제
	case stateWhitelistRemove:
		s += "화이트리스트에서 사용자 삭제:\n\n"
		s += m.inputs[0].View() + "\n\n"
		if m.focusIndex == 1 {
			s += focusedStyle.Render("[ 삭제 실행 ]")
		} else {
			s += fmt.Sprintf("[ %s ]", blurredStyle.Render("삭제 실행"))
		}
		s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 | Enter: 제출 | Esc: 취소")

	case stateReauth:
		s += "보안을 위해 비밀번호를 다시 입력해 주세요:\n\n"
		if m.err != nil {
			s += errorStyle.Render("!! "+formatErrorForUI(m.err)) + "\n\n"
		}
		s += m.reauthInput.View() + "\n\n"
		s += helpStyle.Render("Enter: 확인 | Esc: 취소")

	// 경매 관리 대시보드
	case stateAuctioneerDashboard:
		name := ""
		if m.claims != nil {
			name = fmt.Sprintf(" (%s)", security.SanitizeTUI(m.claims.Username))
		}
		s += fmt.Sprintf("경매 관리 패널%s\n\n", name)
		var menus []string
		if m.claims != nil && m.claims.Role == models.RoleAdmin {
			menus = []string{"새 경매 생성", "경매 목록", "뒤로 관리자 메뉴"}
		} else {
			menus = []string{"새 경매 생성", "경매 목록", "로그아웃"}
		}
		for i, item := range menus {
			if m.menuCursor == i {
				s += focusedStyle.Render("> "+item) + "\n"
			} else {
				s += "  " + item + "\n"
			}
		}
		s += "\n" + helpStyle.Render("j/k 또는 화살표: 이동 | Enter: 선택 | Esc: 뒤로")

	// 경매 생성
	case stateCreateAuction:
		s += "!! 새 블라인드 경매 생성\n\n"
		for i := range m.inputs {
			s += m.inputs[i].View() + "\n"
		}
		if m.err != nil {
			s += "\n" + errorStyle.Render("!! "+formatErrorForUI(m.err)) + "\n"
		}
		s += "\n"
		if m.focusIndex == len(m.inputs) {
			s += focusedStyle.Render("[ 생성 & 키 발급 ]")
		} else {
			s += fmt.Sprintf("[ %s ]", blurredStyle.Render("생성 & 키 발급"))
		}
		s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 | Enter: 제출 | Esc: 뒤로")

	// 경매 목록
	case stateAuctionList:
		s += "전체 경매 목록\n\n"
		if len(m.auctions) == 0 {
			s += helpStyle.Render("경매가 없습니다.") + "\n"
		}
		for i, auc := range m.auctions {
			line := fmt.Sprintf("%s  %-36s  %s",
				renderStatus(auc.Status),
				truncate(security.SanitizeTUI(auc.Title), 36),
				auc.EndAt.Local().Format("01-02 15:04"),
			)
			if i == m.selectedAucIdx {
				s += selectedStyle.Render("> "+line) + "\n"
			} else {
				s += "  " + line + "\n"
			}
		}
		s += "\n" + helpStyle.Render("화살표: 이동 | Enter: 관리 | R: 새로고침 | Esc: 뒤로")

	// 경매 액션 메뉴
	case stateAuctionActions:
		auc := m.auctions[m.selectedAucIdx]
		s += fmt.Sprintf("경매: %s\n", security.SanitizeTUI(auc.Title))
		s += fmt.Sprintf("ID    : %s\n", auc.ID)
		s += fmt.Sprintf("상태  : %s\n", renderStatus(auc.Status))
		s += fmt.Sprintf("시작  : %s\n", auc.StartAt.Local().Format("2006-01-02 15:04"))
		s += fmt.Sprintf("마감  : %s\n\n", auc.EndAt.Local().Format("2006-01-02 15:04"))
		var actions []string
		switch auc.Status {
		case "OPEN":
			actions = []string{"경매 마감하기", "뒤로 가기"}
		case "CLOSED":
			actions = []string{"관리자 승인 수행 (Sign)", "결과 공개 시도 (Reveal)", "뒤로 가기"}
		case "REVEALED":
			actions = []string{"최종 결과 보기", "뒤로 가기"}
		}
		for i, a := range actions {
			if m.menuCursor == i {
				s += focusedStyle.Render("> "+a) + "\n"
			} else {
				s += "  " + a + "\n"
			}
		}
		if auc.Status == "CLOSED" {
			s += "\n" + infoStyle.Render("※ 현재 2명 이상의 관리자 승인이 있어야 복호화가 가능합니다.") + "\n"
		}
		s += "\n" + helpStyle.Render("화살표: 이동 | Enter: 선택 | Esc: 뒤로")

	// 처리 중(스피너)
	case stateAuctionProcessing, stateBidSubmitting:
		s += fmt.Sprintf("\n  %s %s\n", m.spinner.View(), m.processingMsg)

	// 승인 현황
	case stateAuctionApproval:
		auc := m.auctions[m.selectedAucIdx]
		s += infoStyle.Render("경매 복호화 승인 현황") + "\n"
		s += fmt.Sprintf("경매: %s\n\n", security.SanitizeTUI(auc.Title))
		
		s += "승인된 관리자 목록:\n"
		if len(m.approvalTokens) == 0 {
			s += helpStyle.Render("  (아직 승인한 관리자가 없습니다)") + "\n"
		}
		for _, t := range m.approvalTokens {
			s += fmt.Sprintf("  - %s (%s)\n", security.SanitizeTUI(t.AdminID), t.Timestamp.Local().Format("2006-01-02 15:04"))
		}
		
		s += "\n" + successStyle.Render(fmt.Sprintf("현재 승인: %d / 필요 승인: 2", len(m.approvalTokens))) + "\n\n"
		s += focusedStyle.Render("[ Enter: 나도 승인하기 ]") + "\n"
		s += "\n" + helpStyle.Render("Esc: 뒤로")

	// 낙찰 결과
	case stateAuctionResult:
		r := m.auctionResult
		s += "낙찰 결과\n"
		s += fmt.Sprintf("경매 ID: %s\n\n", security.SanitizeTUI(r.AuctionID))
		if r.WinnerUsername != nil && r.WinnerPrice != nil {
			s += winnerStyle.Render(fmt.Sprintf("낙찰자: %s  낙찰가: %d원", security.SanitizeTUI(*r.WinnerUsername), *r.WinnerPrice)) + "\n\n"
		} else {
			s += helpStyle.Render("유효한 입찰자가 없습니다.") + "\n\n"
		}
		s += "순위  사용자ID      검증해시(Proof)   입찰가\n"
		s += "------------------------------------------\n"
		for i, b := range r.Bids {
			priceStr := "N/A"
			if b.Price != nil {
				priceStr = fmt.Sprintf("%d원", *b.Price)
			}
			uid := security.SanitizeTUI(b.UserID)
			if len(uid) > 10 {
				uid = uid[:10] + ".."
			}

			// 검증용 해시 (앞 8자리만 노출하여 무결성 확인용으로 사용)
			proof := "N/A"
			if len(b.CommitHash) >= 8 {
				proof = security.SanitizeTUI(b.CommitHash[:8])
			}

			pfx := "  "
			if r.WinnerID != nil && b.UserID == *r.WinnerID {
				pfx = winnerStyle.Render("> ")
			}
			s += fmt.Sprintf("%s%d. %-12s  [%s...]      %s\n", pfx, i+1, uid, proof, priceStr)
		}
		s += "\n" + helpStyle.Render("아무 키나 눌러 계속...")

	// 서명 키 설정 중
	case stateKeySetup:
		s += fmt.Sprintf("\n  %s 서명 키 확인 중...\n", m.spinner.View())

	// 입찰자 대시보드
	case stateBidderDashboard:
		s += successStyle.Render(fmt.Sprintf("!! %s님! 환영합니다 (BIDDER)", security.SanitizeTUI(m.claims.Username))) + "\n"
		if m.newKeyGenerated {
			s += keyNoticeStyle.Render(fmt.Sprintf("!! 새 개인 서명 키 발급: %s  (안전하게 보관하세요)", m.keyPath)) + "\n"
		}
		s += "\n"
		menus := []string{"경매 목록 보기", "로그아웃"}
		for i, item := range menus {
			if m.menuCursor == i {
				s += focusedStyle.Render("> "+item) + "\n"
			} else {
				s += "  " + item + "\n"
			}
		}
		s += "\n" + helpStyle.Render("화살표: 이동 | Enter: 선택 | Esc: 로그아웃")

	// 입찰자 경매 목록
	case stateBidderAuctionList:
		s += infoStyle.Render("경매 목록") + "\n"
		s += helpStyle.Render("OPEN: 입찰 가능 | REVEALED: 결과 조회 가능") + "\n\n"
		if m.err != nil {
			s += errorStyle.Render("!! "+formatErrorForUI(m.err)) + "\n\n"
		}
		if len(m.auctions) == 0 {
			s += helpStyle.Render("진행 중인 경매가 없습니다.") + "\n"
		}
		for i, auc := range m.auctions {
			line := fmt.Sprintf("%s  %-36s  마감: %s",
				renderStatus(auc.Status),
				truncate(security.SanitizeTUI(auc.Title), 36),
				auc.EndAt.Local().Format("01-02 15:04"),
			)
			if i == m.selectedAucIdx {
				s += selectedStyle.Render("> "+line) + "\n"
			} else {
				s += "  " + line + "\n"
			}
		}
		s += "\n" + helpStyle.Render("화살표: 이동 | Enter: 선택 | R: 새로고침 | Esc: 뒤로")

	// 입찰가 입력
	case stateBidInput:
		auc := m.auctions[m.selectedAucIdx]
		s += infoStyle.Render("입찰: "+security.SanitizeTUI(auc.Title)) + "\n"
		s += fmt.Sprintf("마감: %s\n\n", auc.EndAt.Local().Format("2006-01-02 15:04"))
		s += "입찰가는 RSA-4096으로 암호화되어 마감 전까지 공개되지 않습니다.\n\n"
		s += m.inputs[0].View() + "\n\n"
		if m.err != nil {
			s += errorStyle.Render("!! "+formatErrorForUI(m.err)) + "\n\n"
		}
		if m.focusIndex == len(m.inputs) {
			s += focusedStyle.Render("[ 입찰 제출 (암호화 + 서명) ]")
		} else {
			s += fmt.Sprintf("[ %s ]", blurredStyle.Render("입찰 제출 (암호화 + 서명)"))
		}
		s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 | Enter: 제출 | Esc: 취소")

	// 입찰 완료
	case stateBidSuccess:
		s += successStyle.Render("!! 입찰이 제출되었습니다.") + "\n\n"
		if len(m.auctions) > 0 && m.selectedAucIdx < len(m.auctions) {
			s += fmt.Sprintf("경매: %s\n", m.auctions[m.selectedAucIdx].Title)
		}
		s += infoStyle.Render("입찰가가 암호화되어 저장되었습니다. 마감 후 결과를 확인하세요.") + "\n"
		s += "\n" + helpStyle.Render("아무 키나 눌러 목록으로...")
	}

	return s
}

// ---------------------------------------------------------
//  헬퍼 함수
// ---------------------------------------------------------

func renderStatus(status string) string {
	switch status {
	case "OPEN":
		return statusOpenStyle.Render("[OPEN  ]")
	case "CLOSED":
		return statusClosedStyle.Render("[CLOSED]")
	case "REVEALED":
		return statusRevStyle.Render("[REVLD ]")
	default:
		return "[" + status + "]"
	}
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-3]) + "..."
}

// resetToLogin은 로그인 화면으로 입력 필드를 초기화하며 돌아갑니다.
func (m model) resetToLogin() (model, tea.Cmd) {
	m.state = stateInput
	m.err = nil
	m.setupLoginInputs()
	return m, m.inputs[0].Focus()
}

// doLogout은 세션을 종료하고 로그인 화면으로 돌아갑니다.
func (m model) doLogout() (model, tea.Cmd) {
	if m.authenticator != nil && m.token != "" {
		if err := m.authenticator.Logout(m.token); err != nil {
			log.Error("LOGOUT_FAIL", "", m.claims.UserID, "", err.Error(), "")
		}
	}
	m.token = ""
	m.claims = nil
	m.state = stateInput
	m.err = nil
	m.setupLoginInputs()
	return m, m.inputs[0].Focus()
}

func (m *model) setupCreateAuctionInputs() {
	m.state = stateCreateAuction
	m.err = nil
	m.inputs = make([]textinput.Model, 3)
	m.inputs[0] = textinput.New()
	m.inputs[0].Placeholder = "경매 제목"
	m.inputs[0].Focus()
	m.inputs[1] = textinput.New()
	m.inputs[1].Placeholder = "시작 시각 (YYYY-MM-DD HH:MM)"
	m.inputs[2] = textinput.New()
	m.inputs[2].Placeholder = "종료 시각 (YYYY-MM-DD HH:MM)"
	m.focusIndex = 0
}

type createAuctionMsg struct {
	err error
}

func doCreateAuction(s *auction.Service, creatorID string, title string, start, end time.Time) tea.Cmd {
	return func() tea.Msg {
		_, err := s.CreateAuction(creatorID, auction.CreateAuctionInput{
			Title: title, StartAt: start, EndAt: end,
		})
		return createAuctionMsg{err: err}
	}
}

func (m model) submitCreateAuction() (tea.Model, tea.Cmd) {
	title := strings.TrimSpace(m.inputs[0].Value())
	startStr := strings.TrimSpace(m.inputs[1].Value())
	endStr := strings.TrimSpace(m.inputs[2].Value())

	var start, end time.Time
	var parseErr error
	loc := time.Local
	for _, layout := range []string{"2006-01-02 15:04", "2006-01-02 15:04:05"} {
		start, parseErr = time.ParseInLocation(layout, startStr, loc)
		if parseErr == nil {
			end, parseErr = time.ParseInLocation(layout, endStr, loc)
			if parseErr == nil {
				break
			}
		}
	}
	if parseErr != nil {
		m.err = fmt.Errorf("날짜 형식 오류. YYYY-MM-DD HH:MM 형식으로 입력하세요")
		return m, nil
	}

	// 1. 즉시 로딩 상태로 변경
	m.state = stateAuctionProcessing
	m.processingMsg = fmt.Sprintf("'%s' 경매 생성 및 보안 키 발급 중...", security.SanitizeTUI(title))
	m.err = nil

	// 2. 비동기 커맨드 실행
	return m, tea.Batch(m.spinner.Tick, doCreateAuction(m.auctionService, m.claims.UserID, title, start, end))
}

// ---------------------------------------------------------
//  메인
// ---------------------------------------------------------

func Run() error {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
