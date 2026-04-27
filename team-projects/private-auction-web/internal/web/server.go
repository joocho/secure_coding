package web

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"blind-auction-go/internal/admin"
	"blind-auction-go/internal/auction"
	"blind-auction-go/internal/bid"
	"blind-auction-go/internal/db"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/auth"
	"blind-auction-go/pkg/models"
)

//go:embed templates/*.html static/*
var embedFS embed.FS

// Deps는 웹 서버가 의존하는 서비스들을 모아둡니다.
type Deps struct {
	Auth             auth.Authenticator
	UserStore        *db.UserStore
	WhitelistStore   *db.WhitelistStore
	WhitelistService *admin.WhitelistService
	AuctionService   *auction.Service
	BidService       *bid.Service
	Audit            *security.AuditLogger
}

// Server는 블라인드 경매 웹 서버입니다.
type Server struct {
	Deps
	templates map[string]*template.Template
}

// NewServer는 새로운 웹 서버를 생성합니다.
func NewServer(d Deps) *Server {
	s := &Server{Deps: d}
	s.loadTemplates()
	return s
}

// ListenAndServe는 주어진 주소에서 서버를 시작합니다.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// 정적 파일
	staticFS, _ := fs.Sub(embedFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// 공개 경로
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /register", s.handleRegisterForm)
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// 인증 필요
	mux.HandleFunc("GET /dashboard", s.handleDashboard)

	// 경매
	mux.HandleFunc("GET /auctions", s.handleAuctionList)
	mux.HandleFunc("GET /auctions/new", s.handleAuctionNewForm)
	mux.HandleFunc("POST /auctions/new", s.handleAuctionCreate)
	mux.HandleFunc("GET /auctions/{id}", s.handleAuctionDetail)
	mux.HandleFunc("POST /auctions/{id}/close", s.handleAuctionClose)
	mux.HandleFunc("POST /auctions/{id}/approve", s.handleAuctionApprove)
	mux.HandleFunc("POST /auctions/{id}/reveal", s.handleAuctionReveal)
	mux.HandleFunc("GET /auctions/{id}/result", s.handleAuctionResult)
	mux.HandleFunc("POST /auctions/{id}/bid", s.handleBidSubmit)

	// 관리자
	mux.HandleFunc("GET /admin/whitelist", s.handleWhitelistList)
	mux.HandleFunc("POST /admin/whitelist/add", s.handleWhitelistAdd)
	mux.HandleFunc("POST /admin/whitelist/remove", s.handleWhitelistRemove)
	mux.HandleFunc("GET /admin/users", s.handleUsersList)
	mux.HandleFunc("POST /admin/users/ban", s.handleUserBan)

	return s.logMiddleware(s.recoverMiddleware(s.csrfMiddleware(s.authMiddleware(mux))))
}

func (s *Server) loadTemplates() {
	funcs := template.FuncMap{
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"statusKo": func(st string) string {
			switch st {
			case "OPEN":
				return "진행중"
			case "CLOSED":
				return "마감"
			case "REVEALED":
				return "결과공개"
			default:
				return st
			}
		},
		"roleKo": func(r models.Role) string {
			switch r {
			case models.RoleAdmin:
				return "관리자"
			case models.RoleAuctioneer:
				return "경매진행자"
			case models.RoleBidder:
				return "입찰자"
			case models.RoleGuest:
				return "게스트"
			default:
				return string(r)
			}
		},
		"comma": func(n int) string {
			s := ""
			digits := []byte{}
			for n > 0 {
				digits = append([]byte{byte('0' + n%10)}, digits...)
				n /= 10
			}
			if len(digits) == 0 {
				return "0"
			}
			for i, d := range digits {
				if i > 0 && (len(digits)-i)%3 == 0 {
					s += ","
				}
				s += string(d)
			}
			return s
		},
		"add1": func(i int) int { return i + 1 },
		"deref": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n]
		},
	}

	pages, err := fs.Glob(embedFS, "templates/*.html")
	if err != nil {
		log.Fatalf("템플릿 스캔 실패: %v", err)
	}

	s.templates = make(map[string]*template.Template)
	for _, p := range pages {
		name := filepath.Base(p)
		if name == "layout.html" || strings.HasPrefix(name, "_") {
			continue
		}
		t := template.Must(
			template.New("").Funcs(funcs).ParseFS(embedFS, "templates/layout.html", p),
		)
		s.templates[name] = t
	}
}
