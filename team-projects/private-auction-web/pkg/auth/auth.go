package auth

import (
	"blind-auction-go/internal/db"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/models"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrAuthInvalid   = errors.New("아이디 또는 비밀번호가 올바르지 않습니다")
	ErrAccountLocked = errors.New("계정이 잠시 잠겼습니다. 나중에 다시 시도하세요")
	ErrUserBanned    = errors.New("해당 계정은 관리자에 의해 차단되었습니다")
	ErrExpiredToken  = errors.New("세션이 만료되었습니다")
	ErrInternal      = errors.New("내부 시스템 오류가 발생했습니다")
)

// UserClaims는 인증 토큰에 포함된 사용자 정보를 나타냅니다.
type UserClaims struct {
	UserID   string      `json:"user_id"`
	Username string      `json:"username"`
	Role     models.Role `json:"role"`
}

// LoginHistory는 UI 표시를 위한 로그인 기록 요약입니다.
type LoginHistory struct {
	LastSuccessAt *time.Time
	LastFailedAt  *time.Time
}

// Authenticator는 인증 및 토큰 검증을 위한 인터페이스입니다.
type Authenticator interface {
	Login(username, password string) (string, *LoginHistory, error)
	Logout(token string) error
	ValidateToken(token string) (*UserClaims, string, error)
	Reauthenticate(userID, password string) error // 중요 작업 전 재인증
}

type authenticator struct {
	userStore    *db.UserStore
	sessionStore *db.SessionStore
	whitelist    *db.WhitelistStore
}

// NewAuthenticator는 새로운 Authenticator 구현체를 생성합니다.
func NewAuthenticator(us *db.UserStore, ss *db.SessionStore, ws *db.WhitelistStore) Authenticator {
	return &authenticator{userStore: us, sessionStore: ss, whitelist: ws}
}

// Login은 사용자 인증을 처리하고 세션 토큰을 발급합니다.
func (a *authenticator) Login(username, password string) (string, *LoginHistory, error) {
	// 0. 입력값 유효성 검사 (SQL Injection 및 비정상 입력 방어)
	if !security.ValidateInput(username, 4, 20) {
		return "", nil, ErrAuthInvalid
	}

	user, err := a.userStore.GetByUsername(username)
	if err != nil || user == nil {
		return "", nil, ErrAuthInvalid
	}

	// 화이트리스트를 단일 권한 소스로 사용한다.
	// 미등록 사용자는 항상 GUEST로 처리하고 users.role도 동기화한다.
	effectiveRole, err := a.resolveEffectiveRole(user.Username)
	if err != nil {
		return "", nil, ErrInternal
	}
	if user.Role != effectiveRole {
		if err := a.userStore.UpdateRole(user.ID, effectiveRole); err != nil {
			return "", nil, ErrInternal
		}
		user.Role = effectiveRole
	}

	// 1. 계정 잠금 확인
	if user.LockedUntil != nil {
		if time.Now().Before(*user.LockedUntil) {
			return "", nil, ErrAccountLocked
		}
	}

	// 1.1 차단 여부 확인
	if user.IsBanned {
		return "", nil, ErrUserBanned
	}

	// 2. 비밀번호 검증
	if !security.VerifyPassword(password, user.Salt, user.PasswordHash) {
		// 실패 기록 (5회 실패 시 5분 잠금)
		_ = a.userStore.RecordLoginFailure(user.ID, 5*time.Minute, 5)
		return "", nil, ErrAuthInvalid
	}

	// 3. 성공 기록 및 세션 생성
	_ = a.userStore.ResetLoginFailure(user.ID)
	token := uuid.NewString()
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := a.sessionStore.CreateSession(token, user.ID, expiresAt); err != nil {
		return "", nil, ErrInternal
	}

	loginHist := &LoginHistory{
		LastSuccessAt: user.LastLoginAt,
		LastFailedAt:  user.LastFailedAt,
	}

	return token, loginHist, nil
}

// Logout은 세션을 무효화합니다.
func (a *authenticator) Logout(token string) error {
	return a.sessionStore.DeleteSession(token)
}

// ValidateToken은 세션 토큰의 유효성을 검사합니다.
func (a *authenticator) ValidateToken(token string) (*UserClaims, string, error) {
	sess, err := a.sessionStore.GetSession(token)
	if err != nil {
		return nil, "", ErrExpiredToken
	}

	if time.Now().After(sess.ExpiresAt) {
		_ = a.Logout(token)
		return nil, "", ErrExpiredToken
	}

	user, err := a.userStore.GetByID(sess.UserID)
	if err != nil || user == nil {
		return nil, "", ErrExpiredToken
	}

	// 세션 검증 시에도 화이트리스트 기준으로 유효 역할을 강제한다.
	effectiveRole, err := a.resolveEffectiveRole(user.Username)
	if err != nil {
		return nil, "", ErrInternal
	}
	if user.Role != effectiveRole {
		if err := a.userStore.UpdateRole(user.ID, effectiveRole); err != nil {
			return nil, "", ErrInternal
		}
		user.Role = effectiveRole
	}

	claims := &UserClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
	}

	return claims, token, nil
}

// Reauthenticate는 중요 작업을 수행하기 전 사용자의 비밀번호를 다시 확인합니다.
func (a *authenticator) Reauthenticate(userID string, password string) error {
	user, err := a.userStore.GetByID(userID)
	if err != nil || user == nil {
		return ErrAuthInvalid
	}

	// 1. 계정 잠금 확인
	if user.LockedUntil != nil {
		if time.Now().Before(*user.LockedUntil) {
			return ErrAccountLocked
		}
	}

	// 2. 비밀번호 검증
	if !security.VerifyPassword(password, user.Salt, user.PasswordHash) {
		// 실패 기록 (재인증 실패도 횟수에 포함)
		_ = a.userStore.RecordLoginFailure(user.ID, 5*time.Minute, 5)
		return ErrAuthInvalid
	}

	// 3. 성공 시 실패 기록 초기화
	_ = a.userStore.ResetLoginFailure(user.ID)
	return nil
}

func (a *authenticator) resolveEffectiveRole(username string) (models.Role, error) {
	if a.whitelist == nil {
		return models.RoleGuest, nil
	}
	wlUser, err := a.whitelist.GetByUsername(username)
	if err != nil {
		return "", err
	}
	if wlUser == nil {
		return models.RoleGuest, nil
	}
	return wlUser.AssignedRole, nil
}

// ValidatePassword는 강력한 비밀번호 정책을 검사합니다.
func ValidatePassword(password string) error {
	return security.IsStrongPassword(password)
}
