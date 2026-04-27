package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"blind-auction-go/internal/auction"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/models"
)

func (s *Server) handleAuctionList(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	auctions, err := s.AuctionService.ListAuctions()
	if err != nil {
		s.setFlash(w, "err", "경매 목록 조회 실패")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render(w, r, "auctions.html", map[string]any{
		"Auctions":  auctions,
		"CanCreate": u.Role == models.RoleAdmin || u.Role == models.RoleAuctioneer,
	})
}

func (s *Server) handleAuctionNewForm(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin, models.RoleAuctioneer) {
		return
	}
	s.render(w, r, "auction_new.html", nil)
}

func (s *Server) handleAuctionCreate(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin, models.RoleAuctioneer) {
		return
	}

	title := strings.TrimSpace(r.FormValue("title"))
	start, err := parseDatetimeLocal(r.FormValue("start_at"))
	if err != nil {
		s.setFlash(w, "err", "시작 시각 형식이 잘못되었습니다")
		http.Redirect(w, r, "/auctions/new", http.StatusSeeOther)
		return
	}
	end, err := parseDatetimeLocal(r.FormValue("end_at"))
	if err != nil {
		s.setFlash(w, "err", "종료 시각 형식이 잘못되었습니다")
		http.Redirect(w, r, "/auctions/new", http.StatusSeeOther)
		return
	}

	auc, err := s.AuctionService.CreateAuction(u.UserID, auction.CreateAuctionInput{
		Title: title, StartAt: start, EndAt: end,
	})
	if err != nil {
		s.setFlash(w, "err", err.Error())
		http.Redirect(w, r, "/auctions/new", http.StatusSeeOther)
		return
	}

	s.setFlash(w, "ok", "경매를 생성했습니다")
	http.Redirect(w, r, "/auctions/"+auc.ID, http.StatusSeeOther)
}

func parseDatetimeLocal(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, fmt.Errorf("값이 비어 있습니다")
	}
	layouts := []string{"2006-01-02T15:04", "2006-01-02T15:04:05"}
	var last error
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, v, time.Local); err == nil {
			return t, nil
		} else {
			last = err
		}
	}
	return time.Time{}, last
}

func (s *Server) handleAuctionDetail(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	id := r.PathValue("id")
	auc, err := s.AuctionService.GetAuction(id)
	if err != nil {
		s.setFlash(w, "err", "경매를 찾을 수 없습니다")
		http.Redirect(w, r, "/auctions", http.StatusSeeOther)
		return
	}

	approvals, _ := s.AuctionService.GetApprovalTokens(id)

	s.render(w, r, "auction_detail.html", map[string]any{
		"Auction":         auc,
		"Approvals":       approvals,
		"CanManage":       u.Role == models.RoleAdmin || u.Role == models.RoleAuctioneer,
		"CanBid":          u.Role == models.RoleBidder && auc.Status == "OPEN",
		"CanApprove":      (u.Role == models.RoleAdmin || u.Role == models.RoleAuctioneer) && auc.Status == "CLOSED",
		"AlreadyApproved": userApproved(approvals, u.UserID),
	})
}

func userApproved(approvals []security.ApprovalToken, userID string) bool {
	for _, a := range approvals {
		if a.AdminID == userID {
			return true
		}
	}
	return false
}

func (s *Server) handleAuctionClose(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin, models.RoleAuctioneer) {
		return
	}
	id := r.PathValue("id")
	if err := s.AuctionService.CloseAuction(context.Background(), id); err != nil {
		s.setFlash(w, "err", err.Error())
	} else {
		s.setFlash(w, "ok", "경매를 마감했습니다")
	}
	http.Redirect(w, r, "/auctions/"+id, http.StatusSeeOther)
}

func (s *Server) handleAuctionApprove(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin, models.RoleAuctioneer) {
		return
	}
	id := r.PathValue("id")

	privKey, err := loadUserPrivateKey(u.Username)
	if err != nil {
		s.setFlash(w, "err", "개인키를 로드할 수 없습니다. 다시 로그인해 주세요.")
		http.Redirect(w, r, "/auctions/"+id, http.StatusSeeOther)
		return
	}
	defer security.ZeroingMemory(privKey)

	now := time.Now().UTC()
	payload := fmt.Sprintf("APPROVE:%s:%s", id, now.Format(time.RFC3339))
	sig := security.SignMessage(privKey, []byte(payload))

	if err := s.AuctionService.AddApprovalToken(id, u.UserID, sig, now); err != nil {
		s.setFlash(w, "err", err.Error())
	} else {
		s.setFlash(w, "ok", "승인이 등록되었습니다")
	}
	http.Redirect(w, r, "/auctions/"+id, http.StatusSeeOther)
}

func (s *Server) handleAuctionReveal(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleAdmin, models.RoleAuctioneer) {
		return
	}
	id := r.PathValue("id")
	if err := s.AuctionService.RevealAuctionResults(context.Background(), id); err != nil {
		s.setFlash(w, "err", err.Error())
		http.Redirect(w, r, "/auctions/"+id, http.StatusSeeOther)
		return
	}
	s.setFlash(w, "ok", "결과가 공개되었습니다")
	http.Redirect(w, r, "/auctions/"+id+"/result", http.StatusSeeOther)
}

func (s *Server) handleAuctionResult(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	id := r.PathValue("id")
	result, err := s.AuctionService.GetAuctionResult(id)
	if err != nil {
		s.setFlash(w, "err", err.Error())
		http.Redirect(w, r, "/auctions/"+id, http.StatusSeeOther)
		return
	}
	auc, _ := s.AuctionService.GetAuction(id)

	usernames := map[string]string{}
	for _, b := range result.Bids {
		if _, ok := usernames[b.UserID]; ok {
			continue
		}
		if user, err := s.UserStore.GetByID(b.UserID); err == nil && user != nil {
			usernames[b.UserID] = user.Username
		} else {
			usernames[b.UserID] = b.UserID
		}
	}

	s.render(w, r, "auction_result.html", map[string]any{
		"Auction":   auc,
		"Result":    result,
		"Usernames": usernames,
		"IsWinner":  result.WinnerID != nil && *result.WinnerID == u.UserID,
	})
}
