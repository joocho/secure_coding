// cmd/bid/main.go - 입찰자 전용 터미널 UI
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"blind-auction-go/internal/auction"
	"blind-auction-go/internal/bid"
	"blind-auction-go/internal/db"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/models"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- 스타일링 ---
var (
	titleStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#00875A")).Padding(0, 1).MarginBottom(1)
	focusedStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	errorStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF3340"))
	successStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	helpStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	infoStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB"))
	statusOpenStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	statusRevStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))
	statusOtherStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	winnerStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	selectedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	keyNoticeStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8C00")).Bold(true)
)

type state int

const (
	stateLogin       state = iota
	stateLoggingIn         // 로그인 처리 중
	stateKeySetup          // 서명 키 확인/생성 중
	stateDashboard         // 입찰자 대시보드
	stateAuctionList       // 경매 목록
	stateBidInput          // 입찰가 입력
	stateSubmitting        // 입찰 제출 중
	stateBidSuccess        // 입찰 완료
	stateViewResults       // 낙찰 결과 조회
	stateError             // 오류
)

type model struct {
	state           state
	inputs          []textinput.Model
	focusIndex      int
	user            *models.User
	err             error
	userStore       *db.UserStore
	auctionService  *auction.Service
	bidService      *bid.Service
	spinner         spinner.Model
	menuCursor      int
	auctions        []*models.Auction
	selectedIdx     int
	auctionResult   *auction.AuctionResult
	keyPath         string
	newKeyGenerated bool
	successMsg      string
}

// --- 메시지 타입 ---

type loginDoneMsg struct {
	user *models.User
	err  error
}

type keySetupDoneMsg struct {
	newlyGenerated bool
	keyPath        string
	err            error
}

type auctionsLoadedMsg struct {
	auctions []*models.Auction
	err      error
}

type bidSubmittedMsg struct{ err error }

type resultLoadedMsg struct {
	result *auction.AuctionResult
	err    error
}

// --- 초기화 ---

func initialModel(userStore *db.UserStore, auctionService *auction.Service, bidService *bid.Service) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	m := model{
		state:          stateLogin,
		inputs:         make([]textinput.Model, 2),
		userStore:      userStore,
		auctionService: auctionService,
		bidService:     bidService,
		spinner:        s,
	}

	m.inputs[0] = textinput.New()
	m.inputs[0].Placeholder = "Username"
	m.inputs[0].Focus()
	m.inputs[0].PromptStyle = focusedStyle
	m.inputs[0].TextStyle = focusedStyle

	m.inputs[1] = textinput.New()
	m.inputs[1].Placeholder = "Password"
	m.inputs[1].EchoMode = textinput.EchoPassword
	m.inputs[1].EchoCharacter = '•'

	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

// --- 커맨드 함수 ---

func doLogin(userStore *db.UserStore, username, password string) tea.Cmd {
	return func() tea.Msg {
		username = strings.TrimSpace(username)
		user, err := userStore.GetByUsername(username)
		if err != nil || user == nil {
			return loginDoneMsg{err: fmt.Errorf("아이디 또는 비밀번호가 올바르지 않습니다")}
		}
		if !security.VerifyPassword(password, user.Salt, user.PasswordHash) {
			return loginDoneMsg{err: fmt.Errorf("아이디 또는 비밀번호가 올바르지 않습니다")}
		}
		return loginDoneMsg{user: user}
	}
}

// checkOrSetupKey는 서명 키 파일과 DB 등록 여부를 확인하고 필요시 새로 발급합니다.
// G304(CWE-22) 대응: os.OpenRoot로 파일 접근을 keys/ 디렉토리 내로 제한합니다.
func checkOrSetupKey(userID, username string, userStore *db.UserStore) tea.Cmd {
	return func() tea.Msg {
		// filepath.Base로 경로 컴포넌트(../ 등)를 제거하고 파일명만 추출
		keyFileName := filepath.Base(fmt.Sprintf("%s_ed25519.pem", username))

		// 디렉토리가 없으면 생성
		if err := os.MkdirAll("keys", 0700); err != nil {
			return keySetupDoneMsg{err: fmt.Errorf("keys 디렉터리 생성 실패: %v", err)}
		}

		// os.OpenRoot로 파일 접근 범위를 keys/ 디렉토리로 고정
		root, err := os.OpenRoot("keys")
		if err != nil {
			return keySetupDoneMsg{err: fmt.Errorf("keys 루트 열기 실패: %v", err)}
		}
		defer root.Close()

		// 파일 존재 여부 확인 (root 범위 내에서)
		_, fileErr := root.Stat(keyFileName)
		fileExists := fileErr == nil

		// DB에 공개키 등록 여부 확인
		user, err := userStore.GetByID(userID)
		if err != nil {
			return keySetupDoneMsg{err: fmt.Errorf("사용자 정보 조회 실패: %v", err)}
		}
		dbHasPubKey := user.PublicKey != ""

		// 파일도 있고 DB에도 등록돼 있으면 OK
		keyPath := fmt.Sprintf("keys/%s", keyFileName)
		if fileExists && dbHasPubKey {
			return keySetupDoneMsg{newlyGenerated: false, keyPath: keyPath}
		}

		// 신규 키쌍 발급 필요
		privPEM, pubPEM, err := security.GenerateEd25519KeyPair()
		if err != nil {
			return keySetupDoneMsg{err: fmt.Errorf("키쌍 생성 실패: %v", err)}
		}

		// PEM → raw Ed25519 공개키 바이트 추출
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			return keySetupDoneMsg{err: fmt.Errorf("공개키 파싱 실패")}
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return keySetupDoneMsg{err: fmt.Errorf("공개키 파싱 오류: %v", err)}
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return keySetupDoneMsg{err: fmt.Errorf("Ed25519 키가 아닙니다")}
		}
		pubKeyHex := hex.EncodeToString([]byte(edPub))

		// DB에 공개키 등록
		if err := userStore.UpdatePublicKey(userID, pubKeyHex); err != nil {
			return keySetupDoneMsg{err: fmt.Errorf("공개키 등록 실패: %v", err)}
		}

		// 개인키를 파일에 저장 — root.WriteFile로 keys/ 범위 내에서만 기록
		if err := root.WriteFile(keyFileName, []byte(privPEM), 0600); err != nil {
			return keySetupDoneMsg{err: fmt.Errorf("개인키 저장 실패: %v", err)}
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

// doSubmitBid는 입찰가 암호화 → 서명 → 제출을 처리합니다.
func doSubmitBid(
	bidSvc *bid.Service,
	auctionSvc *auction.Service,
	user *models.User,
	auctionID string,
	price int,
	keyPath string,
) tea.Cmd {
	return func() tea.Msg {
		// 1. 경매 정보 조회 (RSA 공개키 획득)
		auc, err := auctionSvc.GetAuction(auctionID) //여기에서 경매의 공개키 가져옴!(있다면)
		if err != nil {
			return bidSubmittedMsg{err: fmt.Errorf("경매 정보 조회 실패: %v", err)}
		}

		// 2. 입찰 페이로드 생성 {price, nonce}
		dek := make([]byte, 32) // 32바이트 DEK 생성
		if _, err := rand.Read(dek); err != nil {
			return bidSubmittedMsg{err: fmt.Errorf("DEK 생성 실패: %v", err)}
		}
		nonceBytes := make([]byte, 12)
		if _, err := rand.Read(nonceBytes); err != nil {
			return bidSubmittedMsg{err: fmt.Errorf("Nonce 생성 실패: %v", err)}
		}
		nonceStr := base64.StdEncoding.EncodeToString(nonceBytes)

		// 3. AES-GCM 암호화
		priceData := []byte(strconv.Itoa(price))
		block, _ := aes.NewCipher(dek)
		aesGcm, _ := cipher.NewGCM(block)
		ciphertextBid := aesGcm.Seal(nil, nonceBytes, priceData, nil) //DEK로 입찰가priceData 암호화

		// 4. DEK를 경매의 공개키(RSA이고, KEK임)로 암호화함
		encryptedDEK, err := security.EncryptRSA(auc.PublicKey, dek)
		if err != nil {
			return bidSubmittedMsg{err: fmt.Errorf("암호화 실패: %v", err)}
		}

		// 5. 3번에서 말했던 GenerateCommitment 함수 여기서 나옴
		commitHash := security.GenerateCommitment(price, nonceStr, user.ID)

		// 6. Ed25519 서명 — os.OpenRoot로 keys/ 범위 내에서만 읽기 (G304/CWE-22 방지)
		root, err := os.OpenRoot("keys")
		if err != nil {
			return bidSubmittedMsg{err: fmt.Errorf("keys 루트 열기 실패: %v", err)}
		}
		defer root.Close()
		privPEMBytes, err := root.ReadFile(filepath.Base(keyPath))
		if err != nil {
			return bidSubmittedMsg{err: fmt.Errorf("서명 키 파일 없음: %v", err)}
		}
		privKey, err := security.LoadEd25519PrivateKey(string(privPEMBytes))
		if err != nil {
			return bidSubmittedMsg{err: fmt.Errorf("서명 키 로드 실패: %v", err)}
		}
		defer security.ZeroingMemory(privKey)

		// 7. 암호화된 페이로드에 서명
		signedPayload := fmt.Sprintf("%s:%x:%x:%s", auc.ID, encryptedDEK, ciphertextBid, commitHash)
		signature := security.SignMessage(privKey, []byte(signedPayload))

		// 8. 입찰 제출 (서비스 레이어: 서명 검증 + DB 저장)
		_, err = bidSvc.SubmitBid(user.ID, auc.ID, encryptedDEK, ciphertextBid, nonceStr, commitHash, signature)
		if err != nil {
			return bidSubmittedMsg{err: fmt.Errorf("입찰 제출 실패: %v", err)}
		}

		return bidSubmittedMsg{err: nil}
	}
}

func loadResult(svc *auction.Service, auctionID string) tea.Cmd {
	return func() tea.Msg {
		result, err := svc.GetAuctionResult(auctionID)
		return resultLoadedMsg{result: result, err: err}
	}
}

// --- 업데이트 함수 ---

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit

		case "esc":
			switch m.state {
			case stateDashboard:
				return m, tea.Quit
			case stateAuctionList:
				m.state = stateDashboard
				return m, nil
			case stateBidInput:
				m.state = stateAuctionList
				m.focusIndex = 0
				return m, nil
			case stateBidSuccess:
				m.state = stateAuctionList
				return m, loadAuctions(m.auctionService)
			case stateViewResults:
				m.state = stateAuctionList
				return m, nil
			case stateError:
				if m.user != nil {
					m.state = stateDashboard
				} else {
					m.state = stateLogin
				}
				m.err = nil
				return m, nil
			default:
				return m, tea.Quit
			}
		}

		switch m.state {
		case stateLogin:
			s := msg.String()
			if s == "tab" || s == "shift+tab" || s == "enter" || s == "up" || s == "down" {
				if s == "enter" && m.focusIndex == len(m.inputs) {
					m.state = stateLoggingIn
					return m, tea.Batch(
						m.spinner.Tick,
						doLogin(m.userStore, m.inputs[0].Value(), m.inputs[1].Value()),
					)
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
						m.inputs[i].PromptStyle = focusedStyle
						m.inputs[i].TextStyle = focusedStyle
					} else {
						m.inputs[i].Blur()
						m.inputs[i].PromptStyle = blurredStyle
						m.inputs[i].TextStyle = blurredStyle
					}
				}
				return m, tea.Batch(cmds...)
			}

		case stateDashboard:
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
				case 0: // 경매 목록
					m.state = stateAuctionList
					m.selectedIdx = 0
					return m, loadAuctions(m.auctionService)
				case 1: // 로그아웃
					return m, tea.Quit
				}
			}

		case stateAuctionList:
			switch msg.String() {
			case "up", "k":
				if m.selectedIdx > 0 {
					m.selectedIdx--
				}
			case "down", "j":
				if m.selectedIdx < len(m.auctions)-1 {
					m.selectedIdx++
				}
			case "r":
				return m, loadAuctions(m.auctionService)
			case "enter":
				if len(m.auctions) == 0 {
					return m, nil
				}
				auc := m.auctions[m.selectedIdx]
				switch auc.Status {
				case "OPEN":
					// 입찰 폼으로 이동
					m.state = stateBidInput
					m.inputs = make([]textinput.Model, 1)
					m.inputs[0] = textinput.New()
					m.inputs[0].Placeholder = "입찰가 (숫자, 단위: 원)"
					m.inputs[0].Focus()
					m.inputs[0].PromptStyle = focusedStyle
					m.inputs[0].TextStyle = focusedStyle
					m.focusIndex = 0
				case "REVEALED":
					// 결과 조회
					m.state = stateSubmitting
					return m, tea.Batch(m.spinner.Tick, loadResult(m.auctionService, auc.ID))
				default:
					m.state = stateError
					m.err = fmt.Errorf("이 경매는 현재 '%s' 상태로 입찰/조회가 불가능합니다", auc.Status)
				}
			}

		case stateBidInput:
			s := msg.String()
			if s == "tab" || s == "shift+tab" || s == "enter" || s == "up" || s == "down" {
				if s == "enter" && m.focusIndex == len(m.inputs) {
					// 입찰가 파싱 및 제출
					priceStr := strings.TrimSpace(m.inputs[0].Value())
					price, err := strconv.Atoi(priceStr)
					if err != nil || price <= 0 {
						m.state = stateError
						m.err = fmt.Errorf("입찰가는 0보다 큰 숫자여야 합니다")
						return m, nil
					}
					auc := m.auctions[m.selectedIdx]
					m.state = stateSubmitting
					return m, tea.Batch(
						m.spinner.Tick,
						doSubmitBid(m.bidService, m.auctionService, m.user, auc.ID, price, m.keyPath),
					)
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

		case stateBidSuccess, stateViewResults:
			// 아무 키나 눌러 목록으로 돌아감
			m.state = stateAuctionList
			return m, loadAuctions(m.auctionService)

		case stateError:
			if m.user != nil {
				if m.state == stateError {
					m.state = stateDashboard
				}
			} else {
				m.state = stateLogin
			}
			m.err = nil
			return m, nil
		}

	// --- 메시지 처리 ---

	case loginDoneMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		if msg.user.Role == models.RoleGuest {
			m.state = stateError
			m.err = fmt.Errorf("GUEST 권한입니다. 관리자에게 화이트리스트 등록을 요청하세요")
			return m, nil
		}
		m.user = msg.user
		// 로그인 성공 후 서명 키 확인
		m.state = stateKeySetup
		return m, tea.Batch(
			m.spinner.Tick,
			checkOrSetupKey(m.user.ID, m.user.Username, m.userStore),
		)

	case keySetupDoneMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		m.keyPath = msg.keyPath
		m.newKeyGenerated = msg.newlyGenerated
		m.state = stateDashboard
		m.menuCursor = 0
		return m, nil

	case auctionsLoadedMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		m.auctions = msg.auctions
		return m, nil

	case bidSubmittedMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		m.state = stateBidSuccess
		return m, nil

	case resultLoadedMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		m.auctionResult = msg.result
		m.state = stateViewResults
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	// 텍스트 입력 업데이트
	if m.state == stateLogin || m.state == stateBidInput {
		cmds := make([]tea.Cmd, len(m.inputs))
		for i := range m.inputs {
			m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
		}
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

// --- 뷰 함수 ---

func (m model) View() string {
	var s string
	s += titleStyle.Render(" BLIND AUCTION - 입찰자 패널 ") + "\n\n"

	switch m.state {
	case stateLogin:
		s += "계정으로 로그인하세요.\n\n"
		for i := range m.inputs {
			s += m.inputs[i].View() + "\n"
		}
		s += "\n"
		if m.focusIndex == len(m.inputs) {
			s += focusedStyle.Render("[ 로그인 ]")
		} else {
			s += blurredStyle.Render("[ 로그인 ]")
		}
		s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 • Enter: 확인 • Ctrl+C: 종료")

	case stateLoggingIn:
		s += fmt.Sprintf("\n  %s 인증 중...\n", m.spinner.View())

	case stateKeySetup:
		s += fmt.Sprintf("\n  %s 서명 키 확인 중...\n", m.spinner.View())

	case stateDashboard:
		s += successStyle.Render(fmt.Sprintf("✔ 안녕하세요, %s (%s)", m.user.Username, m.user.Role)) + "\n"
		if m.newKeyGenerated {
			s += keyNoticeStyle.Render(fmt.Sprintf("⚠  새 Ed25519 서명 키가 발급되었습니다: %s", m.keyPath)) + "\n"
			s += keyNoticeStyle.Render("   이 파일을 안전하게 보관하세요!") + "\n"
		}
		s += "\n"
		menus := []string{"경매 목록 보기", "로그아웃"}
		for i, item := range menus {
			if i == m.menuCursor {
				s += focusedStyle.Render("▶ "+item) + "\n"
			} else {
				s += "  " + item + "\n"
			}
		}
		s += "\n" + helpStyle.Render("↑/↓ 또는 j/k: 이동 • Enter: 선택 • Ctrl+C: 종료")

	case stateAuctionList:
		s += infoStyle.Render("경매 목록") + "\n"
		s += helpStyle.Render("OPEN: 입찰 가능 | REVEALED: 결과 조회 가능") + "\n\n"
		if len(m.auctions) == 0 {
			s += helpStyle.Render("진행 중인 경매가 없습니다.") + "\n"
		}
		for i, auc := range m.auctions {
			status := renderAuctionStatus(auc.Status)
			endTime := auc.EndAt.Local().Format("01-02 15:04")
			line := fmt.Sprintf("%s  %-36s  마감: %s",
				status,
				truncate(auc.Title, 36),
				endTime,
			)
			if i == m.selectedIdx {
				s += selectedStyle.Render("▶ "+line) + "\n"
			} else {
				s += "  " + line + "\n"
			}
		}
		s += "\n" + helpStyle.Render("↑/↓: 이동 • Enter: 선택 • R: 새로고침 • Esc: 뒤로")

	case stateBidInput:
		auc := m.auctions[m.selectedIdx]
		s += infoStyle.Render("입찰하기: "+auc.Title) + "\n"
		s += fmt.Sprintf("경매 ID  : %s\n", auc.ID)
		s += fmt.Sprintf("마감 시각: %s\n", auc.EndAt.Local().Format("2006-01-02 15:04"))
		s += successStyle.Render("서명 키  : 등록됨 ✓") + "\n\n"
		s += "입찰가를 입력하세요. 입찰가는 RSA-4096으로 암호화되어\n"
		s += "경매 마감 전까지 공개되지 않습니다.\n\n"
		s += m.inputs[0].View() + "\n\n"
		if m.focusIndex == len(m.inputs) {
			s += focusedStyle.Render("[ 입찰 제출 (암호화 + 서명) ]")
		} else {
			s += blurredStyle.Render("[ 입찰 제출 (암호화 + 서명) ]")
		}
		s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 • Enter: 제출 • Esc: 취소")

	case stateSubmitting:
		s += fmt.Sprintf("\n  %s 처리 중...\n", m.spinner.View())

	case stateBidSuccess:
		s += successStyle.Render("✔ 입찰이 성공적으로 제출되었습니다!") + "\n\n"
		auc := m.auctions[m.selectedIdx]
		s += fmt.Sprintf("경매: %s\n", auc.Title)
		s += infoStyle.Render("입찰가는 암호화되어 저장되었습니다. 마감 후 결과를 확인하세요.") + "\n"
		s += "\n" + helpStyle.Render("아무 키나 눌러 목록으로 돌아가기")

	case stateViewResults:
		r := m.auctionResult
		s += infoStyle.Render("낙찰 결과") + "\n"
		s += fmt.Sprintf("경매 ID: %s\n\n", r.AuctionID)
		if r.WinnerUsername != nil && r.WinnerPrice != nil {
			s += winnerStyle.Render(fmt.Sprintf("🏆 낙찰자: %s  낙찰가: %d원", *r.WinnerUsername, *r.WinnerPrice)) + "\n\n"
		} else {
			s += helpStyle.Render("유효한 입찰이 없습니다.") + "\n\n"
		}
		if len(r.Bids) > 0 {
			s += "전체 입찰 결과 (최고가 순):\n"
			for i, b := range r.Bids {
				priceStr := "N/A"
				if b.Price != nil {
					priceStr = fmt.Sprintf("%d원", *b.Price)
				}
				userShort := b.UserID
				if len(b.UserID) > 8 {
					userShort = b.UserID[:8] + "..."
				}
				prefix := "  "
				if r.WinnerID != nil && b.UserID == *r.WinnerID {
					prefix = winnerStyle.Render("★ ")
				}
				s += fmt.Sprintf("%s%d위. %s — %s\n", prefix, i+1, userShort, priceStr)
			}
		}
		s += "\n" + helpStyle.Render("아무 키나 눌러 목록으로 돌아가기")

	case stateError:
		s += errorStyle.Render("✘ 오류 발생") + "\n"
		if m.err != nil {
			s += m.err.Error() + "\n\n"
		}
		s += helpStyle.Render("아무 키나 눌러 계속...")
	}

	return s
}

// --- 헬퍼 함수 ---

func renderAuctionStatus(status string) string {
	switch status {
	case "OPEN":
		return statusOpenStyle.Render("[OPEN  ]")
	case "CLOSED":
		return statusOtherStyle.Render("[CLOSED]")
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

// --- 메인 ---

func main() {
	conn, err := db.InitDB("db/blind_auction.db")
	if err != nil {
		fmt.Printf("DB 오류: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	userStore := db.NewUserStore(conn)
	audit := security.NewAuditLogger(conn)
	auctionService := auction.NewService(conn, audit)
	bidService := bid.NewService(conn, audit)

	p := tea.NewProgram(initialModel(userStore, auctionService, bidService))
	if _, err := p.Run(); err != nil {
		fmt.Printf("실행 오류: %v\n", err)
		os.Exit(1)
	}
}
