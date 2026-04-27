// new  화이트리스트 기반 권한 체크
// 관리가 권환 부여

package admin

import (
	"database/sql"
	"fmt"
	"time"

	"blind-auction-go/internal/db"
	"blind-auction-go/internal/log"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/auth"
	appErrors "blind-auction-go/pkg/errors"
	"blind-auction-go/pkg/models"
)

// WhitelistService는 ADMIN의 화이트리스트 관리를 담당합니다.
type WhitelistService struct {
	db             *sql.DB
	auth           auth.Authenticator
	whitelistStore *db.WhitelistStore
}

// NewWhitelistService는 WhitelistService를 생성합니다.
func NewWhitelistService(dbConn *sql.DB, authenticator auth.Authenticator) *WhitelistService {
	return &WhitelistService{
		db:             dbConn,
		auth:           authenticator,
		whitelistStore: db.NewWhitelistStore(dbConn),
	}
}

// AddToWhitelist는 사용자 이름과 권한을 화이트리스트에 추가합니다.
// 오직 ADMIN 역할만 호출이 가능합니다.
func (s *WhitelistService) AddToWhitelist(token string, username string, role models.Role) error {
	// 1. ADMIN 권한 확인
	claims, _, err := s.auth.ValidateToken(token)
	if err != nil {
		return appErrors.ErrAuthInvalid
	}

	// SecurityGuard를 통해 관리자 권한 확인 및 username 검증
	cleanUsername, err := security.SecurityGuard(claims.UserID, claims.Role, username, models.RoleAdmin)
	if err != nil {
		return err
	}

	// 2. 역할 검증 (GUEST는 화이트리스트에 넣지 않음, 화이트리스트에 없으면 자동 GUEST)
	if role != models.RoleBidder && role != models.RoleAuctioneer && role != models.RoleAdmin {
		return fmt.Errorf("invalid role: %s", role)
	}

	// 3. Store를 통해 추가 및 동기화
	err = s.whitelistStore.AddUserToWhitelist(cleanUsername, role)
	if err != nil {
		log.Error("WHITELIST_ADD_FAIL", cleanUsername, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return appErrors.ErrSystemError
	}

	log.Audit("WHITELIST_ADDED", cleanUsername, claims.UserID, "", fmt.Sprintf("사용자 %s 가 %s 권한으로 화이트리스트에 등록됨", cleanUsername, role))
	return nil
}

// RemoveFromWhitelist는 화이트리스트에서 해당 사용자를 제거합니다.
func (s *WhitelistService) RemoveFromWhitelist(token string, username string) error {
	// 1. ADMIN 권한 확인
	claims, _, err := s.auth.ValidateToken(token)
	if err != nil {
		return appErrors.ErrAuthInvalid
	}

	cleanUsername, err := security.SecurityGuard(claims.UserID, claims.Role, username, models.RoleAdmin)
	if err != nil {
		return err
	}

	// 2. Store를 통해 제거 및 동기화
	err = s.whitelistStore.RemoveUserFromWhitelist(cleanUsername)
	if err != nil {
		log.Error("WHITELIST_REMOVE_FAIL", cleanUsername, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return appErrors.ErrSystemError
	}

	log.Audit("WHITELIST_REMOVED", cleanUsername, claims.UserID, "", "화이트리스트에서 제거됨 (role → GUEST)")
	return nil
}

// GetWhitelist는 현재 화이트리스트 전체를 조회합니다.
func (s *WhitelistService) GetWhitelist(token string) ([]models.WhitelistUser, error) {
	// 1. ADMIN 권한 확인
	claims, _, err := s.auth.ValidateToken(token)
	if err != nil {
		return nil, appErrors.ErrAuthInvalid
	}

	if _, err := security.SecurityGuard(claims.UserID, claims.Role, "GET_LIST", models.RoleAdmin); err != nil {
		return nil, err
	}

	// 2. SELECT
	const q = `SELECT username, assigned_role, created_at FROM whitelist_users ORDER BY created_at DESC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	defer rows.Close()

	var list []models.WhitelistUser
	for rows.Next() {
		var u models.WhitelistUser
		var createdAt string
		if err := rows.Scan(&u.Username, &u.AssignedRole, &createdAt); err != nil {
			return nil, appErrors.ErrSystemError
		}
		u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		list = append(list, u)
	}

	return list, nil
}

// DetermineRole은 사용자명에 따라 화이트리스트에 있는지 확인하여 역할을 결정합니다.
// 회원가입(Signup) 로직에서 사용되는 팀 A·B용 인터페이스입니다.
func (s *WhitelistService) DetermineRole(username string) models.Role {
	const q = `SELECT assigned_role FROM whitelist_users WHERE username = ?`
	var role string
	err := s.db.QueryRow(q, username).Scan(&role)
	if err != nil {
		// 화이트리스트에 없거나 에러 발생 시 기본적으로 GUEST 역할을 부여합니다.
		return models.RoleGuest
	}

	return models.Role(role)
}
