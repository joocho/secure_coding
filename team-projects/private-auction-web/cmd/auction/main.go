package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"blind-auction-go/internal/auction"
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
	titleStyle        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#7D56F4")).Padding(0, 1).MarginBottom(1)
	focusedStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	errorStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF3340"))
	successStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	helpStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	adminMenuStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	statusOpenStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	statusClosedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8C00"))
	statusRevStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))
	winnerStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	selectedRowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
)

type state int

const (
	stateLogin          state = iota
	stateLoggingIn            // 로그인 처리 중 (스피너)
	stateDashboard            // 메인 대시보드
	stateCreateAuction        // 경매 생성 폼
	stateAuctionList          // 경매 목록
	stateAuctionActions       // 선택한 경매의 액션 메뉴
	stateProcessing           // 마감/공개 처리 중 (스피너)
	stateAuctionResult        // 결과 조회
	stateSuccess              // 성공 메시지
	stateError                // 오류 메시지
)

type model struct {
	state          state
	inputs         []textinput.Model
	focusIndex     int
	user           *models.User
	err            error
	userStore      *db.UserStore
	auctionService *auction.Service
	successMsg     string
	spinner        spinner.Model
	menuCursor     int
	auctions       []*models.Auction
	selectedIdx    int
	auctionResult  *auction.AuctionResult
	processingMsg  string
}

// --- 메시지 타입 ---

type loginDoneMsg struct {
	user *models.User
	err  error
}

type auctionsLoadedMsg struct {
	auctions []*models.Auction
	err      error
}

type opDoneMsg struct{ err error }

type auctionResultMsg struct {
	result *auction.AuctionResult
	err    error
}

// --- 초기화 ---

func initialModel(userStore *db.UserStore, auctionService *auction.Service) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	m := model{
		state:          stateLogin,
		inputs:         make([]textinput.Model, 2),
		userStore:      userStore,
		auctionService: auctionService,
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

func loadAuctions(svc *auction.Service) tea.Cmd {
	return func() tea.Msg {
		auctions, err := svc.ListAuctions()
		return auctionsLoadedMsg{auctions: auctions, err: err}
	}
}

func doCloseAuction(svc *auction.Service, id string) tea.Cmd {
	return func() tea.Msg {
		err := svc.CloseAuction(context.Background(), id)
		return opDoneMsg{err: err}
	}
}

func doRevealAuction(svc *auction.Service, id string) tea.Cmd {
	return func() tea.Msg {
		err := svc.RevealAuctionResults(context.Background(), id)
		return opDoneMsg{err: err}
	}
}

func doLoadResult(svc *auction.Service, id string) tea.Cmd {
	return func() tea.Msg {
		result, err := svc.GetAuctionResult(id)
		return auctionResultMsg{result: result, err: err}
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
			case stateCreateAuction, stateSuccess:
				m.state = stateDashboard
				m.err = nil
				return m, nil
			case stateError:
				if m.user != nil {
					m.state = stateDashboard
				} else {
					m.state = stateLogin
				}
				m.err = nil
				return m, nil
			case stateAuctionList:
				m.state = stateDashboard
				return m, nil
			case stateAuctionActions:
				m.state = stateAuctionList
				m.menuCursor = 0
				return m, nil
			case stateAuctionResult:
				m.state = stateAuctionActions
				m.menuCursor = 0
				return m, nil
			default:
				return m, tea.Quit
			}
		}

		// 상태별 키 처리
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
				if m.menuCursor < 2 {
					m.menuCursor++
				}
			case "enter":
				switch m.menuCursor {
				case 0: // 경매 생성
					m.setupCreateAuctionInputs()
					return m, nil
				case 1: // 경매 목록
					m.state = stateAuctionList
					m.selectedIdx = 0
					return m, loadAuctions(m.auctionService)
				case 2: // 로그아웃
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
				if len(m.auctions) > 0 {
					m.state = stateAuctionActions
					m.menuCursor = 0
				}
			}

		case stateAuctionActions:
			auc := m.auctions[m.selectedIdx]
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
				if m.menuCursor == 1 {
					// 뒤로 가기
					m.state = stateAuctionList
					m.menuCursor = 0
					return m, nil
				}
				// 첫 번째 액션 실행
				switch auc.Status {
				case "OPEN":
					m.state = stateProcessing
					m.processingMsg = fmt.Sprintf("'%s' 경매를 마감 중...", auc.Title)
					return m, tea.Batch(m.spinner.Tick, doCloseAuction(m.auctionService, auc.ID))
				case "CLOSED":
					m.state = stateProcessing
					m.processingMsg = fmt.Sprintf("'%s' 결과 공개 중...", auc.Title)
					return m, tea.Batch(m.spinner.Tick, doRevealAuction(m.auctionService, auc.ID))
				case "REVEALED":
					m.state = stateProcessing
					m.processingMsg = "결과 불러오는 중..."
					return m, tea.Batch(m.spinner.Tick, doLoadResult(m.auctionService, auc.ID))
				}
			}

		case stateCreateAuction:
			s := msg.String()
			if s == "tab" || s == "shift+tab" || s == "enter" || s == "up" || s == "down" {
				if s == "enter" && m.focusIndex == len(m.inputs) {
					return m.submitCreateAuction()
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

		case stateSuccess, stateError:
			// 아무 키나 누르면 돌아감 (Esc 이외 키)
			if m.state == stateSuccess {
				m.state = stateDashboard
			} else {
				if m.user != nil {
					m.state = stateDashboard
				} else {
					m.state = stateLogin
				}
				m.err = nil
			}
			return m, nil
		}

	// --- 메시지 처리 ---

	case loginDoneMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		if msg.user.Role != models.RoleAdmin && msg.user.Role != models.RoleAuctioneer {
			m.state = stateError
			m.err = fmt.Errorf("접근 권한 없음: %s 역할은 이 도구를 사용할 수 없습니다", msg.user.Role)
			return m, nil
		}
		m.user = msg.user
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

	case opDoneMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		// 성공 후 경매 목록으로 돌아가며 새로고침
		m.state = stateAuctionList
		return m, loadAuctions(m.auctionService)

	case auctionResultMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		m.auctionResult = msg.result
		m.state = stateAuctionResult
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	// 텍스트 입력 업데이트
	if m.state == stateLogin || m.state == stateCreateAuction {
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
	s += titleStyle.Render(" BLIND AUCTION - 경매 관리 패널 ") + "\n\n"

	switch m.state {
	case stateLogin:
		s += "ADMIN 또는 AUCTIONEER 계정으로 로그인하세요.\n\n"
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

	case stateDashboard:
		s += successStyle.Render(fmt.Sprintf("✔ 안녕하세요, %s (%s)", m.user.Username, m.user.Role)) + "\n\n"
		menus := []string{"새 경매 생성", "경매 목록 보기", "로그아웃"}
		for i, item := range menus {
			if i == m.menuCursor {
				s += focusedStyle.Render("▶ "+item) + "\n"
			} else {
				s += "  " + item + "\n"
			}
		}
		s += "\n" + helpStyle.Render("↑/↓ 또는 j/k: 이동 • Enter: 선택 • Ctrl+C: 종료")

	case stateCreateAuction:
		s += adminMenuStyle.Render("새 경매 생성") + "\n"
		s += "새 블라인드 경매 정보를 입력하세요.\n\n"
		for i := range m.inputs {
			s += m.inputs[i].View() + "\n"
		}
		s += "\n"
		if m.focusIndex == len(m.inputs) {
			s += focusedStyle.Render("[ 생성 & 키 발급 ]")
		} else {
			s += blurredStyle.Render("[ 생성 & 키 발급 ]")
		}
		s += "\n\n" + helpStyle.Render("Tab/화살표: 이동 • Enter: 제출 • Esc: 뒤로")

	case stateAuctionList:
		s += adminMenuStyle.Render("전체 경매 목록") + "\n\n"
		if len(m.auctions) == 0 {
			s += helpStyle.Render("경매가 없습니다. 먼저 경매를 생성하세요.") + "\n"
		}
		for i, auc := range m.auctions {
			status := renderStatus(auc.Status)
			endTime := auc.EndAt.Local().Format("01-02 15:04")
			line := fmt.Sprintf("%s  %-36s  %s",
				status,
				truncate(auc.Title, 36),
				endTime,
			)
			if i == m.selectedIdx {
				s += selectedRowStyle.Render("▶ "+line) + "\n"
			} else {
				s += "  " + line + "\n"
			}
		}
		s += "\n" + helpStyle.Render("↑/↓: 이동 • Enter: 관리 • R: 새로고침 • Esc: 뒤로")

	case stateAuctionActions:
		auc := m.auctions[m.selectedIdx]
		s += adminMenuStyle.Render("경매 관리: "+auc.Title) + "\n"
		s += fmt.Sprintf("ID     : %s\n", auc.ID)
		s += fmt.Sprintf("상태   : %s\n", renderStatus(auc.Status))
		s += fmt.Sprintf("시작   : %s\n", auc.StartAt.Local().Format("2006-01-02 15:04"))
		s += fmt.Sprintf("마감   : %s\n\n", auc.EndAt.Local().Format("2006-01-02 15:04"))

		var actions []string
		switch auc.Status {
		case "OPEN":
			actions = []string{"경매 마감하기", "뒤로 가기"}
		case "CLOSED":
			actions = []string{"결과 공개하기 (복호화)", "뒤로 가기"}
		case "REVEALED":
			actions = []string{"낙찰 결과 보기", "뒤로 가기"}
		}
		for i, action := range actions {
			if i == m.menuCursor {
				s += focusedStyle.Render("▶ "+action) + "\n"
			} else {
				s += "  " + action + "\n"
			}
		}
		s += "\n" + helpStyle.Render("↑/↓: 이동 • Enter: 선택 • Esc: 뒤로")

	case stateProcessing:
		s += fmt.Sprintf("\n  %s %s\n", m.spinner.View(), m.processingMsg)

	case stateAuctionResult:
		r := m.auctionResult
		s += adminMenuStyle.Render("낙찰 결과") + "\n"
		s += fmt.Sprintf("경매 ID: %s\n\n", r.AuctionID)
		if r.WinnerUsername != nil && r.WinnerPrice != nil {
			s += winnerStyle.Render(fmt.Sprintf("🏆 낙찰자: %s  낙찰가: %d원", *r.WinnerUsername, *r.WinnerPrice)) + "\n\n"
		} else {
			s += helpStyle.Render("유효한 입찰이 없습니다.") + "\n\n"
		}
		if len(r.Bids) > 0 {
			s += "전체 입찰 (최고가 순):\n"
			for i, b := range r.Bids {
				priceStr := "N/A"
				if b.Price != nil {
					priceStr = fmt.Sprintf("%d원", *b.Price)
				}
				userShort := b.UserID
				if len(b.UserID) > 8 {
					userShort = b.UserID[:8] + "..."
				}
				s += fmt.Sprintf("  %d위. %s — %s\n", i+1, userShort, priceStr)
			}
		}
		s += "\n" + helpStyle.Render("Esc: 뒤로")

	case stateSuccess:
		s += successStyle.Render("✔ 성공!") + "\n"
		s += m.successMsg + "\n\n"
		s += helpStyle.Render("아무 키나 눌러 계속...")

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

func (m *model) setupCreateAuctionInputs() {
	m.state = stateCreateAuction
	m.inputs = make([]textinput.Model, 3)

	m.inputs[0] = textinput.New()
	m.inputs[0].Placeholder = "경매 제목 (예: 희귀 미술품 #1)"
	m.inputs[0].Focus()

	m.inputs[1] = textinput.New()
	m.inputs[1].Placeholder = "시작 시각 (YYYY-MM-DD HH:MM)"

	m.inputs[2] = textinput.New()
	m.inputs[2].Placeholder = "종료 시각 (YYYY-MM-DD HH:MM)"

	m.focusIndex = 0
}

func (m model) submitCreateAuction() (tea.Model, tea.Cmd) {
	title := strings.TrimSpace(m.inputs[0].Value())
	startStr := strings.TrimSpace(m.inputs[1].Value())
	endStr := strings.TrimSpace(m.inputs[2].Value())

	// YYYY-MM-DD HH:MM 또는 YYYY-MM-DD HH:MM:SS 모두 허용
	var start, end time.Time
	var parseErr error
	for _, layout := range []string{"2006-01-02 15:04", "2006-01-02 15:04:05"} {
		start, parseErr = time.Parse(layout, startStr)
		if parseErr == nil {
			end, parseErr = time.Parse(layout, endStr)
			if parseErr == nil {
				break
			}
		}
	}

	if parseErr != nil {
		m.state = stateError
		m.err = fmt.Errorf("날짜 형식 오류. YYYY-MM-DD HH:MM 형식으로 입력하세요")
		return m, nil
	}

	auc, err := m.auctionService.CreateAuction(m.user.ID, auction.CreateAuctionInput{
		Title:   title,
		StartAt: start,
		EndAt:   end,
	})
	if err != nil {
		m.state = stateError
		m.err = fmt.Errorf("경매 생성 실패: %v", err)
		return m, nil
	}

	m.state = stateSuccess
	m.successMsg = fmt.Sprintf("경매 '%s' 생성 완료!\nID: %s\nRSA 키쌍이 안전하게 발급되었습니다.", auc.Title, auc.ID)
	return m, nil
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

	p := tea.NewProgram(initialModel(userStore, auctionService))
	if _, err := p.Run(); err != nil {
		fmt.Printf("실행 오류: %v\n", err)
		os.Exit(1)
	}
}
