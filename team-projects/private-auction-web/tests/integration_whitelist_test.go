package tests

import (
	"database/sql"
	"testing"
	"time"

	"blind-auction-go/internal/admin"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/models"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB는 메모리 상에 테스트용 DB를 초기화합니다.
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// whitelist_users 테이블 생성 (schema.sql 기준)
	schema := `
	CREATE TABLE whitelist_users (
		username TEXT PRIMARY KEY,
		assigned_role TEXT NOT NULL CHECK (assigned_role IN ('BIDDER', 'AUCTIONEER', 'ADMIN')),
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	return db
}

func TestWhitelistIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// 1. 화이트리스트 서비스 초기화 (Authenticator는 여기서 테스트하지 않으므로 nil 주입)
	// 핵심은 WhitelistService.DetermineRole() 과 security.CheckRole()의 연동입니다.
	whitelistSvc := admin.NewWhitelistService(db, nil)

	// 2. [ADMIN 액션] 화이트리스트에 사용자 등록 (BIDDER 역할)
	_, err := db.Exec("INSERT INTO whitelist_users (username, assigned_role, created_at) VALUES (?, ?, ?)",
		"approved_user", "BIDDER", time.Now().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to insert whitelist: %v", err)
	}

	// 3. [Signup 액션] 회원가입 시 역할 결정 테스트

	// 시나리오 A: 화이트리스트에 등록된 유저 ('approved_user')
	roleA := whitelistSvc.DetermineRole("approved_user")
	if roleA != models.RoleBidder {
		t.Errorf("Expected BIDDER role, but got %s", roleA)
	}

	// 시나리오 B: 화이트리스트에 없는 유저 ('anonymous')
	roleB := whitelistSvc.DetermineRole("anonymous")
	if roleB != models.RoleGuest {
		t.Errorf("Expected GUEST role, but got %s", roleB)
	}

	// 4. [보안 가드 검증] 역할에 따른 행위 제한 테스트

	// 시나리오 A: BIDDER 유저가 경매 입찰(commit) 시도 -> 성공 기대
	// PhaseGuard는 내부적으로 rbac.go의 CanAccessAuctionPhase를 호출합니다.
	err = security.PhaseGuard("user_id_123", roleA, "OPEN", "commit")
	if err != nil {
		t.Errorf("BIDDER role should be able to commit in OPEN phase, but got error: %v", err)
	}

	// 시나리오 B: GUEST 유저가 경매 입찰(commit) 시도 -> 차단 기대
	err = security.PhaseGuard("user_id_456", roleB, "OPEN", "commit")
	if err == nil {
		t.Error("보안 오류: GUEST 역할의 사용자가 입찰(commit)에 접근하는 것이 허용되었습니다.")
	}

	// 시나리오 C: GUEST 유저가 경매 생성(create) 시도 -> 차단 기대
	err = security.PhaseGuard("user_id_456", roleB, "OPEN", "create")
	if err == nil {
		t.Error("보안 오류: GUEST 역할의 사용자가 경매 생성(create)에 접근하는 것이 허용되었습니다.")
	}
}
