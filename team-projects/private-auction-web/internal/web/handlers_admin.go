package web

import (
	"net/http"
	"strings"

	"blind-auction-go/pkg/models"
)

func (s *Server) handleWhitelistList(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin) {
		return
	}

	users, err := s.WhitelistService.GetWhitelist(getToken(r))
	if err != nil {
		s.setFlash(w, "err", err.Error())
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render(w, r, "whitelist.html", map[string]any{
		"Whitelist": users,
	})
}

func (s *Server) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin) {
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	role := models.Role(strings.TrimSpace(r.FormValue("role")))

	if err := s.WhitelistService.AddToWhitelist(getToken(r), username, role); err != nil {
		s.setFlash(w, "err", err.Error())
	} else {
		s.setFlash(w, "ok", "화이트리스트에 추가되었습니다")
	}
	http.Redirect(w, r, "/admin/whitelist", http.StatusSeeOther)
}

func (s *Server) handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin) {
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	if err := s.WhitelistService.RemoveFromWhitelist(getToken(r), username); err != nil {
		s.setFlash(w, "err", err.Error())
	} else {
		s.setFlash(w, "ok", "화이트리스트에서 제거되었습니다")
	}
	http.Redirect(w, r, "/admin/whitelist", http.StatusSeeOther)
}

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin) {
		return
	}
	users, err := s.UserStore.GetAllUsers()
	if err != nil {
		s.setFlash(w, "err", "사용자 목록 조회 실패")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render(w, r, "users.html", map[string]any{
		"Users": users,
	})
}

func (s *Server) handleUserBan(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin) {
		return
	}

	userID := strings.TrimSpace(r.FormValue("user_id"))
	action := r.FormValue("action") // "ban" 또는 "unban"
	if userID == "" {
		s.setFlash(w, "err", "사용자 ID가 필요합니다")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	if userID == u.UserID {
		s.setFlash(w, "err", "자기 자신을 차단할 수 없습니다")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}

	isBanned := action == "ban"
	if err := s.UserStore.SetBanStatus(userID, isBanned); err != nil {
		s.setFlash(w, "err", err.Error())
	} else if isBanned {
		s.setFlash(w, "ok", "사용자를 차단했습니다")
	} else {
		s.setFlash(w, "ok", "차단을 해제했습니다")
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}
