package cli

import (
	"database/sql"
	"fmt"
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

// --- 통합 앱 상태 정의 ---
type appState int

const (
	stateLogin appState = iota
	stateLoggingIn
	stateAdminDashboard
	stateBidderDashboard
	stateError
)

type mainModel struct {
	state      appState
	user       *models.User
	err        error
	inputs     []textinput.Model
	focusIndex int
	spinner    spinner.Model

	// 서비스 레이어
	userStore      *db.UserStore
	whitelistStore *db.WhitelistStore
	auctionService *auction.Service
	bidService     *bid.Service
}

// --- 메시지 타입 ---
type loginDoneMsg struct {
	user *models.User
	err  error
}

func InitialModel(dbConn *sql.DB) mainModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	m := mainModel{
		state:          stateLogin,
		inputs:         make([]textinput.Model, 2),
		userStore:      db.NewUserStore(dbConn),
		whitelistStore: db.NewWhitelistStore(dbConn),
		auctionService: auction.NewService(dbConn, security.NewAuditLogger(dbConn)),
		bidService:     bid.NewService(dbConn, security.NewAuditLogger(dbConn)),
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
	m.inputs[1].PromptStyle = blurredStyle
	m.inputs[1].TextStyle = blurredStyle

	return m
}

func (m mainModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.state == stateError {
				m.state = stateLogin
				m.err = nil
				return m, nil
			}
			return m, tea.Quit
		case "tab", "shift+tab", "up", "down":
			if m.state == stateLogin {
				if msg.String() == "up" || msg.String() == "shift+tab" {
					m.focusIndex--
				} else {
					m.focusIndex++
				}
				if m.focusIndex > 1 {
					m.focusIndex = 0
				} else if m.focusIndex < 0 {
					m.focusIndex = 1
				}

				for i := range m.inputs {
					if i == m.focusIndex {
						m.inputs[i].Focus()
						m.inputs[i].PromptStyle = focusedStyle
						m.inputs[i].TextStyle = focusedStyle
					} else {
						m.inputs[i].Blur()
						m.inputs[i].PromptStyle = blurredStyle
						m.inputs[i].TextStyle = blurredStyle
					}
				}
				return m, nil
			}
		case "enter":
			if m.state == stateLogin {
				m.state = stateLoggingIn
				return m, tea.Batch(
					m.spinner.Tick,
					doUnifiedLogin(m.userStore, m.whitelistStore, m.inputs[0].Value(), m.inputs[1].Value()),
				)
			}
		}

	case loginDoneMsg:
		if msg.err != nil {
			m.state = stateError
			m.err = msg.err
			return m, nil
		}
		m.user = msg.user
		if m.user.Role == models.RoleAdmin || m.user.Role == models.RoleAuctioneer {
			m.state = stateAdminDashboard
		} else {
			m.state = stateBidderDashboard
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	// 텍스트 입력 업데이트 (상태가 Login일 때만 키 이벤트를 각 input에 전달)
	if m.state == stateLogin {
		for i := range m.inputs {
			var cmd tea.Cmd
			m.inputs[i], cmd = m.inputs[i].Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// 스타일링
var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#7D56F4")).Padding(0, 1).MarginBottom(1)
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF3340"))
	helpStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	focusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

func (m mainModel) View() string {
	var s string
	s += titleStyle.Render(" 🛡️  SECURE BLIND AUCTION SYSTEM ") + "\n\n"

	switch m.state {
	case stateLogin:
		s += "계정 정보를 입력하세요.\n\n"
		for i := range m.inputs {
			s += m.inputs[i].View() + "\n"
		}
		s += "\n" + helpStyle.Render("Tab/화살표: 이동 • Enter: 로그인 • Ctrl+C: 종료")

	case stateLoggingIn:
		s += fmt.Sprintf("\n  %s 인증 중...\n", m.spinner.View())

	case stateAdminDashboard:
		s += successStyle.Render(fmt.Sprintf("✔ 관리자 모드: %s (%s)", m.user.Username, m.user.Role)) + "\n\n"
		s += "경매 관리 기능을 준비 중입니다...\n"
		s += helpStyle.Render("Esc: 종료")

	case stateBidderDashboard:
		s += successStyle.Render(fmt.Sprintf("✔ 입찰자 모드: %s (%s)", m.user.Username, m.user.Role)) + "\n\n"
		s += "입찰 참여 기능을 준비 중입니다...\n"
		s += helpStyle.Render("Esc: 종료")

	case stateError:
		s += errorStyle.Render("✘ 오류 발생") + "\n"
		if m.err != nil {
			s += m.err.Error() + "\n\n"
		}
		s += helpStyle.Render("Esc를 눌러 로그인으로 돌아가기")
	}

	return s
}

func doUnifiedLogin(us *db.UserStore, ws *db.WhitelistStore, username, password string) tea.Cmd {
	return func() tea.Msg {
		username = strings.TrimSpace(username)
		user, err := us.GetByUsername(username)
		if err != nil || user == nil {
			return loginDoneMsg{err: fmt.Errorf("아이디 또는 비밀번호가 올바르지 않습니다")}
		}
		if !security.VerifyPassword(password, user.Salt, user.PasswordHash) {
			return loginDoneMsg{err: fmt.Errorf("아이디 또는 비밀번호가 올바르지 않습니다")}
		}

		wl, err := ws.GetByUsername(username)
		if err != nil {
			return loginDoneMsg{err: fmt.Errorf("권한 검증 중 오류가 발생했습니다")}
		}
		if wl == nil || wl.AssignedRole == models.RoleGuest {
			return loginDoneMsg{err: fmt.Errorf("화이트리스트 미등록 사용자입니다. 관리자에게 권한 요청하세요")}
		}
		if user.Role != wl.AssignedRole {
			if err := us.UpdateRole(user.ID, wl.AssignedRole); err != nil {
				return loginDoneMsg{err: fmt.Errorf("권한 동기화 중 오류가 발생했습니다")}
			}
			user.Role = wl.AssignedRole
		}

		return loginDoneMsg{user: user}
	}
}

func StartUnifiedApp(dbConn *sql.DB) {
	p := tea.NewProgram(InitialModel(dbConn))
	if _, err := p.Run(); err != nil {
		fmt.Printf("실행 오류: %v\n", err)
	}
}

func RunSetup(dbConn *sql.DB) {
	userStore := db.NewUserStore(dbConn)
	fmt.Println("⚙️  시스템 초기화 중...")

	// 1. 관리자 계정 생성
	saltBytes, _ := security.GenerateSaltBytes(16)
	hash := security.HashPassword("admin123", saltBytes)
	_, err := userStore.CreateUser("admin", hash, saltBytes, models.RoleAdmin)
	if err != nil {
		fmt.Printf("❌ 관리자 계정 생성 실패: %v\n", err)
	} else {
		fmt.Println("✅ 관리자 계정 생성 완료 (ID: admin, PW: admin123)")
	}

	// 2. 입찰자 계정 생성
	saltBytes2, _ := security.GenerateSaltBytes(16)
	hash2 := security.HashPassword("user123", saltBytes2)
	_, err = userStore.CreateUser("user", hash2, saltBytes2, models.RoleBidder)
	if err != nil {
		fmt.Printf("❌ 입찰자 계정 생성 실패: %v\n", err)
	} else {
		fmt.Println("✅ 입찰자 계정 생성 완료 (ID: user, PW: user123)")
	}

	fmt.Println("\n🚀 이제 'blind-auction.exe'를 실행하여 로그인하세요!")
}
