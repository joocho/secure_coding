// 화이트 리스트 등록 및 조회 관리가 가능한 db 부분
package db

import (
	"database/sql"
	"errors"
	"strings" // 추가
	"time"

	"blind-auction-go/pkg/models"
)

// WhitelistStore는 SQLite를 사용하여 화이트리스트 사용자 정보를 관리합니다.
type WhitelistStore struct {
	db *sql.DB
}

// NewWhitelistStore는 새로운 WhitelistStore를 생성합니다.
func NewWhitelistStore(db *sql.DB) *WhitelistStore {
	return &WhitelistStore{db: db}
}

// GetByUsername은 화이트리스트에서 특정 사용자를 조회합니다.
//
// 주요 사용 시점:
//   - 회원가입 시: 사전 등록 여부를 확인하여 초기 역할을 결정합니다.
//     (등록됨 → 해당 역할 즉시 부여 / 미등록 → GUEST 부여)
//
// 반환값: 화이트리스트에 없으면 (nil, nil) 반환 (에러 아님)
func (s *WhitelistStore) GetByUsername(username string) (*models.WhitelistUser, error) {
	username = strings.TrimSpace(username) // 공백 제거
	const q = `SELECT username, assigned_role, created_at FROM whitelist_users WHERE username = ?`

	var u models.WhitelistUser
	var roleStr, createdAt string

	err := s.db.QueryRow(q, username).Scan(&u.Username, &roleStr, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // 화이트리스트 미등록 (에러 아님)
		}
		return nil, err
	}

	u.AssignedRole = models.Role(roleStr)
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &u, nil
}

// AddUserToWhitelist는 사용자를 화이트리스트에 추가하거나 기존 사용자라면 역할을 업데이트합니다.
// 또한 이미 가입한 사용자라면 users 테이블의 role도 동기화합니다.
func (s *WhitelistStore) AddUserToWhitelist(username string, role models.Role) error {
	username = strings.TrimSpace(username)     // 공백 제거
	roleStr := strings.TrimSpace(string(role)) // 공백 제거

	const q = `
		INSERT INTO whitelist_users (username, assigned_role, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET assigned_role = excluded.assigned_role`

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(q, username, roleStr, now)
	if err != nil {
		return err
	}

	// users 테이블 동기화 (이미 가입한 사용자일 경우)
	_, err = s.db.Exec(`UPDATE users SET role = ? WHERE username = ?`, roleStr, username)
	return err
}

// RemoveUserFromWhitelist는 사용자를 화이트리스트에서 삭제합니다.
// 또한 이미 가입한 사용자라면 users 테이블의 role을 GUEST로 강등시킵니다.
func (s *WhitelistStore) RemoveUserFromWhitelist(username string) error {
	username = strings.TrimSpace(username) // 공백 제거
	const q = `DELETE FROM whitelist_users WHERE username = ?`
	_, err := s.db.Exec(q, username)
	if err != nil {
		return err
	}

	// users 테이블 동기화 (이미 가입한 사용자일 경우 GUEST로 강등)
	_, err = s.db.Exec(`UPDATE users SET role = ? WHERE username = ?`, string(models.RoleGuest), username)
	return err
}

// GetAllWhitelistUsers는 등록된 모든 화이트리스트 사용자를 조회합니다.
func (s *WhitelistStore) GetAllWhitelistUsers() ([]models.WhitelistUser, error) {
	const q = `SELECT username, assigned_role, created_at FROM whitelist_users`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.WhitelistUser
	for rows.Next() {
		var u models.WhitelistUser
		var roleStr string
		var createdAt string
		if err := rows.Scan(&u.Username, &roleStr, &createdAt); err != nil {
			return nil, err
		}
		u.AssignedRole = models.Role(roleStr)
		u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		users = append(users, u)
	}
	return users, nil
}
