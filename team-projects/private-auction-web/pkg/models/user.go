package models

import "time"

// Role은 시스템 내 사용자 권한 등급을 나타냅니다.
// A·B팀 auth 구현 시 이 타입을 반드시 사용해야 합니다.
type Role string

const (
	// RoleBidder는 경매 참여(Commit/Reveal)만 가능합니다.
	RoleBidder Role = "BIDDER"
	// RoleAuctioneer는 경매를 등록하고 마감할 수 있습니다.
	RoleAuctioneer Role = "AUCTIONEER"
	// RoleAdmin은 모든 권한을 가집니다.
	RoleAdmin Role = "ADMIN"
	// 추가 화이트리스트에서 등록되지 않는 사용자가 제한된 행위만 할수있게
	// RoleGuest는 읽기만 가능하며, 입찰이나 낙찰이 불가능합니다.
	RoleGuest Role = "GUEST"
)

// User는 시스템에 등록된 사용자를 나타냅니다.
// DB의 users 테이블과 1:1로 대응됩니다.
//
// ⚠️  A·B팀 주의사항:
//   - Password는 반드시 Argon2id 해시값만 저장합니다 (평문 절대 금지).
//   - Salt는 사용자마다 crypto/rand로 생성한 16바이트 이상 값이어야 합니다.
//   - Role은 위의 Role 상수 중 하나여야 합니다.
type User struct {
	ID           string     `json:"id"`       // UUID v4
	Username     string     `json:"username"` // 로그인 식별자 (unique)
	PasswordHash string     `json:"-"`        // Argon2id 해시 (hex 인코딩)
	Salt         []byte     `json:"-"`        // Argon2id용 솔트 (>= 16 bytes, crypto/rand 생성)
	Role         Role       `json:"role"`     // BIDDER | AUCTIONEER | ADMIN
	CreatedAt    time.Time  `json:"created_at"`
	PublicKey    string     `json:"public_key"`               // Ed25519 Public Key (PEM or HEX)
	Fingerprint    string     `json:"fingerprint"`               // 공개키 지문 (SHA-256)
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`  // 마지막 로그인 성공 시각 (nullable)
	LastFailedAt   *time.Time `json:"last_failed_at,omitempty"` // 마지막 로그인 실패 시각 (nullable)
	FailedAttempts int        `json:"failed_attempts"`          // 로그인 실패 횟수
	LockedUntil    *time.Time `json:"locked_until,omitempty"`    // 계정 잠금 만료 시각 (nullable)
	IsBanned       bool       `json:"is_banned"`                // 관리자에 의한 차단 여부
}
