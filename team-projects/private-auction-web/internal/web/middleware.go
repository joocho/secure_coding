package web

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"time"

	"blind-auction-go/pkg/auth"
	"blind-auction-go/pkg/models"
)

const (
	sessionCookieName = "session"
	flashCookieName   = "flash"
)

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxToken
)

// authMiddleware는 쿠키의 세션 토큰을 검증하여 UserClaims을 context에 저장합니다.
// 토큰이 없거나 무효하면 user=nil로 통과시킵니다 (핸들러가 명시적으로 체크).
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		claims, token, err := s.Auth.ValidateToken(c.Value)
		if err != nil {
			// 만료 쿠키 제거
			clearCookie(w, sessionCookieName)
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, claims)
		ctx = context.WithValue(ctx, ctxToken, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrfMiddleware는 POST 요청에서 Origin/Referer가 Host와 일치하는지 확인합니다.
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}
		host := r.Host
		origin := r.Header.Get("Origin")
		if origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != host {
				http.Error(w, "CSRF: invalid Origin", http.StatusForbidden)
				return
			}
		} else {
			ref := r.Header.Get("Referer")
			if ref == "" {
				http.Error(w, "CSRF: missing Origin/Referer", http.StatusForbidden)
				return
			}
			u, err := url.Parse(ref)
			if err != nil || u.Host != host {
				http.Error(w, "CSRF: invalid Referer", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC %s %s: %v", r.Method, r.URL.Path, rec)
				http.Error(w, "서버 오류가 발생했습니다", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start))
	})
}

// ── 헬퍼 ──────────────────────────────────────────────────────

func getUser(r *http.Request) *auth.UserClaims {
	if v := r.Context().Value(ctxUser); v != nil {
		return v.(*auth.UserClaims)
	}
	return nil
}

func getToken(r *http.Request) string {
	if v := r.Context().Value(ctxToken); v != nil {
		return v.(string)
	}
	return ""
}

// requireUser는 로그인되어 있지 않으면 /login으로 리다이렉트하고 nil을 반환합니다.
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) *auth.UserClaims {
	u := getUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	return u
}

// requireRole은 주어진 역할 중 하나가 아닌 경우 403 페이지를 보여줍니다.
func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, u *auth.UserClaims, allowed ...models.Role) bool {
	for _, role := range allowed {
		if u.Role == role {
			return true
		}
	}
	s.setFlash(w, "err", "해당 작업에 대한 권한이 없습니다.")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	return false
}

// ── 세션 & 플래시 쿠키 ───────────────────────────────────────

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   24 * 60 * 60, // 24h
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// setFlash는 한 번만 표시되는 알림을 쿠키에 저장합니다. kind: "ok" 또는 "err".
func (s *Server) setFlash(w http.ResponseWriter, kind, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    kind + "|" + url.QueryEscape(msg),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30,
	})
}

// getFlash는 플래시 쿠키를 읽고 즉시 삭제합니다.
func (s *Server) getFlash(w http.ResponseWriter, r *http.Request) (kind, msg string) {
	c, err := r.Cookie(flashCookieName)
	if err != nil {
		return "", ""
	}
	clearCookie(w, flashCookieName)
	parts := splitOnce(c.Value, "|")
	if len(parts) != 2 {
		return "", ""
	}
	decoded, _ := url.QueryUnescape(parts[1])
	return parts[0], decoded
}

func splitOnce(s, sep string) []string {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return []string{s[:i], s[i+len(sep):]}
		}
	}
	return []string{s}
}
