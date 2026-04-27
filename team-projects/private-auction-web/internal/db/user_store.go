package db

import (
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/models"
	"database/sql"
	"github.com/google/uuid"
	"time"
)

type UserStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

// GetByUsername은 사용자명으로 전체 정보를 조회합니다.
func (s *UserStore) GetByUsername(username string) (*models.User, error) {
	const q = `SELECT id, username, password_hash, salt, public_key, fingerprint, role, failed_attempts, locked_until, last_login_at, last_failed_at, is_banned, created_at FROM users WHERE username = ?`
	var u models.User
	var createdAt, roleStr string
	var pubKey, fingerprint, lockedUntil, lastLoginAt, lastFailedAt sql.NullString
	var isBannedInt int
	err := s.db.QueryRow(q, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &pubKey, &fingerprint, &roleStr, &u.FailedAttempts, &lockedUntil, &lastLoginAt, &lastFailedAt, &isBannedInt, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	u.IsBanned = isBannedInt == 1
	u.Role = models.Role(roleStr)
	u.PublicKey = pubKey.String
	u.Fingerprint = fingerprint.String
	if lockedUntil.Valid && lockedUntil.String != "" {
		t, err := time.Parse(time.RFC3339, lockedUntil.String)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", lockedUntil.String)
		}
		if err == nil {
			u.LockedUntil = &t
		}
	}
	if lastLoginAt.Valid && lastLoginAt.String != "" {
		t, err := time.Parse(time.RFC3339, lastLoginAt.String)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", lastLoginAt.String)
		}
		if err == nil {
			u.LastLoginAt = &t
		}
	}
	if lastFailedAt.Valid && lastFailedAt.String != "" {
		t, err := time.Parse(time.RFC3339, lastFailedAt.String)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", lastFailedAt.String)
		}
		if err == nil {
			u.LastFailedAt = &t
		}
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if u.CreatedAt.IsZero() {
		u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	}
	return &u, nil
}

// GetByID는 ID로 사용자 정보를 조회합니다.
func (s *UserStore) GetByID(id string) (*models.User, error) {
	const q = `SELECT id, username, password_hash, salt, public_key, fingerprint, role, failed_attempts, locked_until, last_login_at, last_failed_at, is_banned, created_at FROM users WHERE id = ?`
	var u models.User
	var createdAt, roleStr string
	var pubKey, fingerprint, lockedUntil, lastLoginAt, lastFailedAt sql.NullString
	var failedAttemptsInt, isBannedInt int
	err := s.db.QueryRow(q, id).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &pubKey, &fingerprint, &roleStr, &failedAttemptsInt, &lockedUntil, &lastLoginAt, &lastFailedAt, &isBannedInt, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	u.FailedAttempts = failedAttemptsInt
	u.IsBanned = isBannedInt == 1
	u.Role = models.Role(roleStr)
	u.PublicKey = pubKey.String
	u.Fingerprint = fingerprint.String
	if lockedUntil.Valid && lockedUntil.String != "" {
		t, err := time.Parse(time.RFC3339, lockedUntil.String)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", lockedUntil.String)
		}
		if err == nil {
			u.LockedUntil = &t
		}
	}
	if lastLoginAt.Valid && lastLoginAt.String != "" {
		t, err := time.Parse(time.RFC3339, lastLoginAt.String)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", lastLoginAt.String)
		}
		if err == nil {
			u.LastLoginAt = &t
		}
	}
	if lastFailedAt.Valid && lastFailedAt.String != "" {
		t, err := time.Parse(time.RFC3339, lastFailedAt.String)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", lastFailedAt.String)
		}
		if err == nil {
			u.LastFailedAt = &t
		}
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if u.CreatedAt.IsZero() {
		u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	}
	return &u, nil
}

// CreateUser는 새로운 사용자를 생성합니다. (비밀번호 및 솔트 포함)
func (s *UserStore) CreateUser(username, passwordHash string, salt []byte, role models.Role) (string, error) {
	const q = `INSERT INTO users (id, username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)`
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(q, id, username, passwordHash, salt, string(role), now)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpdatePublicKey는 사용자의 공개키를 업데이트하고 자동으로 지문을 생성합니다.
func (s *UserStore) UpdatePublicKey(userID, publicKey string) error {
	fingerprint := security.CalculatePublicKeyFingerprint(publicKey)
	const q = `UPDATE users SET public_key = ?, fingerprint = ? WHERE id = ?`
	_, err := s.db.Exec(q, publicKey, fingerprint, userID)
	return err
}

// UpdateRole은 사용자의 role을 갱신합니다.
func (s *UserStore) UpdateRole(userID string, role models.Role) error {
	const q = `UPDATE users SET role = ? WHERE id = ?`
	_, err := s.db.Exec(q, string(role), userID)
	return err
}

// RecordLoginFailure는 로그인 실패 기록을 업데이트하고 필요 시 계정을 잠급니다.
func (s *UserStore) RecordLoginFailure(userID string, lockDuration time.Duration, maxAttempts int) error {
	now := time.Now().UTC().Format(time.RFC3339)

	// 현재 실패 횟수 확인
	var attempts int
	err := s.db.QueryRow("SELECT failed_attempts FROM users WHERE id = ?", userID).Scan(&attempts)
	if err != nil {
		return err
	}

	attempts++
	var lockedUntil sql.NullString
	if attempts >= maxAttempts {
		lockedUntil.Valid = true
		lockedUntil.String = time.Now().Add(lockDuration).UTC().Format(time.RFC3339)
	}

	const q = `UPDATE users SET failed_attempts = ?, last_failed_at = ?, locked_until = ? WHERE id = ?`
	_, err = s.db.Exec(q, attempts, now, lockedUntil, userID)
	return err
}

// ResetLoginFailure는 로그인 성공 시 실패 횟수를 초기화하고 마지막 로그인 시각을 기록합니다.
func (s *UserStore) ResetLoginFailure(userID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	const q = `UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`
	_, err := s.db.Exec(q, now, userID)
	return err
}
// SetBanStatus는 사용자의 차단 상태를 변경합니다.
func (s *UserStore) SetBanStatus(userID string, isBanned bool) error {
	val := 0
	if isBanned {
		val = 1
	}
	const q = `UPDATE users SET is_banned = ? WHERE id = ?`
	_, err := s.db.Exec(q, val, userID)
	return err
}

// GetAllUsers는 시스템의 모든 사용자 정보를 조회합니다.
func (s *UserStore) GetAllUsers() ([]models.User, error) {
	const q = `SELECT id, username, role, failed_attempts, is_banned, created_at FROM users ORDER BY created_at DESC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		var roleStr, createdAt string
		var isBannedInt int
		if err := rows.Scan(&u.ID, &u.Username, &roleStr, &u.FailedAttempts, &isBannedInt, &createdAt); err != nil {
			return nil, err
		}
		u.Role = models.Role(roleStr)
		u.IsBanned = isBannedInt == 1
		u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if u.CreatedAt.IsZero() {
			u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		}
		users = append(users, u)
	}
	return users, nil
}
