// 초기 관리자 계정 생성용 스크립트
// 사용법: go run cmd/create_admin/main.go
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"blind-auction-go/internal/db"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/models"

	"github.com/google/uuid"
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

	username := "admin"
	password := "admin123!"
	now := time.Now().UTC().Format(time.RFC3339)

	// 기존 users 테이블 확인
	var existingID string
	err = conn.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&existingID)
	if err == nil {
		fmt.Printf("이미 '%s' 계정이 존재합니다 (ID: %s)\n", username, existingID)
	} else {
		// 솔트 생성
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			log.Fatalf("솔트 생성 실패: %v", err)
		}

		hash := security.HashPassword(password, salt)
		id := uuid.New().String()

		const q = `
			INSERT INTO users (id, username, password_hash, salt, role, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`
		_, err = conn.Exec(q, id, username, hash, salt, string(models.RoleAdmin), now)
		if err != nil {
			log.Fatalf("관리자 계정 생성 실패: %v", err)
		}
		fmt.Println("✅ users 테이블에 관리자 계정 생성 완료")
	}

	// whitelist_users 테이블에도 admin 등록
	const wq = `
		INSERT INTO whitelist_users (username, assigned_role, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET assigned_role = excluded.assigned_role`
	_, err = conn.Exec(wq, username, string(models.RoleAdmin), now)
	if err != nil {
		log.Fatalf("화이트리스트 등록 실패: %v", err)
	}

	fmt.Println("--------------------------------------------------")
	fmt.Println("✅ 관리자 계정 설정 완료!")
	fmt.Println("--------------------------------------------------")
	fmt.Printf("ID:       %s\n", username)
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Role:     %s (화이트리스트 포함)\n", models.RoleAdmin)
	fmt.Println("--------------------------------------------------")
}
