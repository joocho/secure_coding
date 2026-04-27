package db

import (
	"database/sql"
	"time"
)

// SessionStore는 사용자의 세션 정보를 관리합니다.
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore는 새로운 SessionStore를 생성합니다.
func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// Session은 세션 데이터를 나타냅니다.
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

// CreateSession은 새로운 세션을 생성합니다.
func (s *SessionStore) CreateSession(id, userID string, expiresAt time.Time) error {
	_, err := s.db.Exec("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)", id, userID, expiresAt.Format(time.RFC3339))
	return err
}

// GetSession은 세션 정보를 조회합니다.
func (s *SessionStore) GetSession(id string) (*Session, error) {
	var sess Session
	var expStr string
	err := s.db.QueryRow("SELECT id, user_id, expires_at FROM sessions WHERE id = ?", id).Scan(&sess.ID, &sess.UserID, &expStr)
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt, _ = time.Parse(time.RFC3339, expStr)
	return &sess, nil
}

// DeleteSession은 세션을 삭제합니다.
func (s *SessionStore) DeleteSession(id string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	return err
}

// LoginHistoryData는 DB의 로그인 기록을 나타냅니다.
type LoginHistoryData struct {
	UserID         string
	FailedAttempts int
	LockedUntil    *time.Time
	LastSuccessAt  *time.Time
	LastFailedAt   *time.Time
}

// GetLoginHistory는 사용자의 로그인 기록을 조회합니다.
func (s *SessionStore) GetLoginHistory(userID string) (*LoginHistoryData, error) {
	var h LoginHistoryData
	var locked, success, failed sql.NullString
	err := s.db.QueryRow("SELECT user_id, failed_attempts, locked_until, last_success_at, last_failed_at FROM login_history WHERE user_id = ?", userID).
		Scan(&h.UserID, &h.FailedAttempts, &locked, &success, &failed)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if locked.Valid {
		t, _ := time.Parse(time.RFC3339, locked.String)
		h.LockedUntil = &t
	}
	if success.Valid {
		t, _ := time.Parse(time.RFC3339, success.String)
		h.LastSuccessAt = &t
	}
	if failed.Valid {
		t, _ := time.Parse(time.RFC3339, failed.String)
		h.LastFailedAt = &t
	}
	return &h, nil
}

// RecordSuccess는 로그인 성공 기록을 업데이트합니다.
func (s *SessionStore) RecordSuccess(userID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	const q = `
		INSERT INTO login_history (user_id, failed_attempts, last_success_at)
		VALUES (?, 0, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			failed_attempts = 0,
			last_success_at = excluded.last_success_at,
			locked_until = NULL`
	_, err := s.db.Exec(q, userID, now)
	return err
}

// RecordFailure는 로그인 실패 기록을 업데이트합니다. (계정 잠금 정책 포함)
func (s *SessionStore) RecordFailure(userID string, lockDuration time.Duration, maxAttempts int) error {
	now := time.Now().UTC().Format(time.RFC3339)

	// 먼저 현재 실패 횟수를 가져옵니다.
	var attempts int
	err := s.db.QueryRow("SELECT failed_attempts FROM login_history WHERE user_id = ?", userID).Scan(&attempts)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	attempts++
	var lockedUntil sql.NullString
	if attempts >= maxAttempts {
		lockedUntil.Valid = true
		lockedUntil.String = time.Now().Add(lockDuration).UTC().Format(time.RFC3339)
	}

	const q = `
		INSERT INTO login_history (user_id, failed_attempts, last_failed_at, locked_until)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			failed_attempts = excluded.failed_attempts,
			last_failed_at = excluded.last_failed_at,
			locked_until = excluded.locked_until`

	_, err = s.db.Exec(q, userID, attempts, now, lockedUntil)
	return err
}
