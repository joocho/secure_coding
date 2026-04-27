// 화이트리스트 초기 등록 스크립트
// 사용법: go run cmd/seed_whitelist/main.go
package main

import (
	"fmt"
	"log"
	"os"

	"blind-auction-go/internal/db"
	"blind-auction-go/pkg/models"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "db/blind_auction.db"
	}
	conn, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("DB 연결 실패: %v", err)
	}
	defer conn.Close()

	whitelistStore := db.NewWhitelistStore(conn)

	// 초기 등록할 사용자 목록
	whitelist := []struct {
		username string
		role     models.Role
	}{
		{"alice", models.RoleBidder},
		{"bob", models.RoleBidder},
		{"carol", models.RoleAuctioneer},
		{"admin", models.RoleAdmin},
	}

	fmt.Println("--------------------------------------------------")
	fmt.Println("🚀 화이트리스트 초기 데이터 등록 중...")
	fmt.Println("--------------------------------------------------")

	for _, user := range whitelist {
		err := whitelistStore.AddUserToWhitelist(user.username, user.role)
		if err != nil {
			log.Fatalf("[%s] 화이트리스트 등록 실패: %v", user.username, err)
		}
		fmt.Printf("✅ %-10s -> %s\n", user.username, user.role)
	}

	fmt.Println("--------------------------------------------------")
	fmt.Println("✨ 화이트리스트 등록 완료!")
	fmt.Println("--------------------------------------------------")
}
