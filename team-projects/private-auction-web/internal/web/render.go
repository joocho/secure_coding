package web

import (
	"log"
	"net/http"

	"blind-auction-go/pkg/auth"
)

// pageData는 템플릿에 전달되는 공통 컨텍스트입니다.
type pageData struct {
	User      *auth.UserClaims
	FlashKind string
	FlashMsg  string
	Data      map[string]any
}

// render는 주어진 페이지 템플릿을 layout과 함께 렌더합니다.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	t, ok := s.templates[page]
	if !ok {
		log.Printf("template not found: %s", page)
		http.Error(w, "템플릿을 찾을 수 없습니다: "+page, http.StatusInternalServerError)
		return
	}

	kind, msg := s.getFlash(w, r)
	pd := pageData{
		User:      getUser(r),
		FlashKind: kind,
		FlashMsg:  msg,
		Data:      data,
	}
	if pd.Data == nil {
		pd.Data = map[string]any{}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", pd); err != nil {
		log.Printf("render error (%s): %v", page, err)
	}
}
