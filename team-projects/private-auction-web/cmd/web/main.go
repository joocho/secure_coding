// 블라인드 경매 웹 서버 진입점
// 사용법: go run cmd/web/main.go
package main

import (
	"fmt"
	"log"
	"os"

	"blind-auction-go/internal/admin"
	"blind-auction-go/internal/auction"
	"blind-auction-go/internal/bid"
	"blind-auction-go/internal/db"
	"blind-auction-go/internal/security"
	"blind-auction-go/internal/web"
	"blind-auction-go/pkg/auth"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "db/blind_auction.db"
	}

	if err := os.MkdirAll("db", 0750); err != nil {
		log.Fatalf("db 디렉터리 생성 실패: %v", err)
	}
	if err := os.MkdirAll("keys", 0700); err != nil {
		log.Fatalf("keys 디렉터리 생성 실패: %v", err)
	}

	conn, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("DB 초기화 실패: %v", err)
	}
	defer conn.Close()

	userStore := db.NewUserStore(conn)
	sessionStore := db.NewSessionStore(conn)
	whitelistStore := db.NewWhitelistStore(conn)
	authenticator := auth.NewAuthenticator(userStore, sessionStore, whitelistStore)
	auditLogger := security.NewAuditLogger(conn)
	auctionService := auction.NewService(conn, auditLogger)
	bidService := bid.NewService(conn, auditLogger)
	whitelistService := admin.NewWhitelistService(conn, authenticator)

	server := web.NewServer(web.Deps{
		Auth:             authenticator,
		UserStore:        userStore,
		WhitelistStore:   whitelistStore,
		WhitelistService: whitelistService,
		AuctionService:   auctionService,
		BidService:       bidService,
		Audit:            auditLogger,
	})

	addr := os.Getenv("WEB_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	fmt.Printf("🚀 블라인드 경매 웹 서버 시작: http://localhost%s\n", addr)
	if err := server.ListenAndServe(addr); err != nil {
		log.Fatalf("서버 오류: %v", err)
	}
}
