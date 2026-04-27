package web

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/auth"
	"blind-auction-go/pkg/models"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if getUser(r) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if getUser(r) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login.html", nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	token, _, err := s.Auth.Login(username, password)
	if err != nil {
		s.setFlash(w, "err", err.Error())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	setSessionCookie(w, token)

	// 토큰 검증 → 역할별 키 세팅
	claims, _, vErr := s.Auth.ValidateToken(token)
	if vErr == nil && claims != nil && claims.Role != models.RoleGuest {
		if err := ensureUserKey(claims.UserID, claims.Username, s.UserStore); err != nil {
			// 치명적이지는 않음 — 로그인은 유지하되 경고만 전달
			s.setFlash(w, "err", fmt.Sprintf("서명 키 준비 중 오류: %v", err))
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	s.setFlash(w, "ok", fmt.Sprintf("환영합니다, %s 님", username))
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handleRegisterForm(w http.ResponseWriter, r *http.Request) {
	if getUser(r) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render(w, r, "register.html", nil)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if err := registerUser(s, username, password, confirm); err != nil {
		s.setFlash(w, "err", err.Error())
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	s.setFlash(w, "ok", "회원가입 완료. 로그인해 주세요.")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func registerUser(s *Server, username, password, confirm string) error {
	if username == "" {
		return errors.New("아이디를 입력하세요")
	}
	if password != confirm {
		return errors.New("비밀번호가 일치하지 않습니다")
	}
	if err := auth.ValidatePassword(password); err != nil {
		return err
	}

	existing, err := s.UserStore.GetByUsername(username)
	if err != nil {
		return errors.New("내부 오류가 발생했습니다")
	}
	if existing != nil {
		return errors.New("이미 사용 중인 아이디입니다")
	}

	initialRole := models.RoleGuest
	wl, _ := s.WhitelistStore.GetByUsername(username)
	if wl != nil {
		initialRole = wl.AssignedRole
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return errors.New("내부 오류가 발생했습니다")
	}
	hashed := security.HashPassword(password, salt)
	if _, err := s.UserStore.CreateUser(username, hashed, salt, initialRole); err != nil {
		return errors.New("회원가입에 실패했습니다")
	}
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token := getToken(r); token != "" {
		_ = s.Auth.Logout(token)
	}
	clearCookie(w, sessionCookieName)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	s.render(w, r, "dashboard.html", map[string]any{
		"IsAdmin":      u.Role == models.RoleAdmin,
		"IsAuctioneer": u.Role == models.RoleAuctioneer,
		"IsBidder":     u.Role == models.RoleBidder,
		"IsGuest":      u.Role == models.RoleGuest,
	})
}
