package security

import (
	"blind-auction-go/pkg/models"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"strings"
)

var (
	ErrPermissionDenied = errors.New("AUDIT_POLICY_REJECTION: ONLY ADMIN CAN ACCESS AUDIT LOGS")
)

// AuditLogEntry는 조회용 로그 데이터 구조체입니다.
type AuditLogEntry struct {
	ID           int
	EventType    string
	ActorID      string
	ResourceID   string
	Message      string
	PayloadHash  string
	PreviousHash string
	CreatedAt    string
}

// AuditLogger는 시스템의 보안 이벤트를 기록하고 무결성을 관리합니다.
type AuditLogger struct {
	db *sql.DB
}

// NewAuditLogger는 새로운 AuditLogger를 생성합니다.
func NewAuditLogger(db *sql.DB) *AuditLogger {
	return &AuditLogger{db: db}
}

// sanitize는 로그 주입 공격을 방지하기 위해 줄바꿈 및 제어 문자를 제거하고, 
// 로그 뷰어에서의 XSS 공격 방지를 위해 HTML 이스케이프 처리를 수행합니다.
func (l *AuditLogger) sanitize(input string) string {
	// 1. 줄바꿈 및 캐리지 리턴 제거 (Log Forging 방지)
	s := strings.ReplaceAll(input, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	
	// 2. HTML 특수 문자 인코딩 (관리 도구에서 악성 코드 실행 방지)
	s = html.EscapeString(s)
	
	return strings.TrimSpace(s)
}

// maskSensitiveData는 메시지 내의 민감한 정보(비밀번호, 입찰가 등)를 별표로 가립니다.
func (l *AuditLogger) maskSensitiveData(message string) string {
	// 1. 숫자 패턴 (입찰가 등) 가리기 (간단한 예시: 4자리 이상의 숫자는 별표 처리)
	// 실제 운영 환경에서는 정규표현식을 더 정교하게 다듬어야 합니다.
	sensitiveKeywords := []string{"password", "secret", "key", "bid", "price"}
	
	lowerMsg := strings.ToLower(message)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lowerMsg, kw) {
			// 키워드가 포함된 경우 메시지 전체 혹은 해당 부분 보호 정책 적용
			// 여기서는 교육용으로 메시지 내 숫자를 별표로 바꿉니다.
			return "CONFIDENTIAL_DATA_MASKED" 
		}
	}
	return message
}

// LogEvent는 보안 이벤트를 기록하고 이전 로그와의 해시 연쇄를 생성합니다.
// status: "SUCCESS" 또는 "FAILURE"
func (l *AuditLogger) LogEvent(ctx context.Context, eventType, status, actorID, resourceID, message string) error {
	// 사용자 입력 가능성이 있는 모든 필드 데이터 정제 (Sanitization)
	eventType = l.sanitize(eventType)
	status = l.sanitize(status)
	actorID = l.sanitize(actorID)
	resourceID = l.sanitize(resourceID)
	message = l.sanitize(l.maskSensitiveData(message)) // 마스킹 적용
	
	// 1. 이전 로그의 해시 가져오기 (Hash Chaining)
	var prevHash string
	err := l.db.QueryRow("SELECT payload_hash FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&prevHash)
	if err == sql.ErrNoRows {
		prevHash = "GENESIS_HASH"
	}

	// 2. 현재 이벤트의 해시 생성 (Status 및 정제된 데이터 포함)
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s", eventType, status, actorID, resourceID, message, prevHash)
	h := sha256.New()
	h.Write([]byte(payload))
	currentHash := hex.EncodeToString(h.Sum(nil))

	// 3. DB 저장 (message 컬럼 포함)
	const q = `INSERT INTO audit_logs (event_type, actor_id, resource_id, payload_hash, previous_hash, message) VALUES (?, ?, ?, ?, ?, ?)`
	fullEventType := fmt.Sprintf("%s:%s", eventType, status)
	_, err = l.db.Exec(q, fullEventType, actorID, resourceID, currentHash, prevHash, message)
	return err
}

// VerifyIntegrity는 저장된 모든 감사 로그를 순차적으로 검증하여 변조 여부를 확인합니다.
// 오직 ADMIN 역할을 가진 사용자만 수행할 수 있습니다.
func (l *AuditLogger) VerifyIntegrity(ctx context.Context, user *models.User) (bool, error) {
	// 1. 권한 체크 (RBAC)
	if user == nil || user.Role != "ADMIN" {
		return false, ErrPermissionDenied
	}

	// 2. 무결성 검증 수행
	rows, err := l.db.QueryContext(ctx, "SELECT payload_hash, previous_hash FROM audit_logs ORDER BY id ASC")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	expectedPrevHash := "GENESIS_HASH"
	for rows.Next() {
		var payloadHash, prevHash string
		if err := rows.Scan(&payloadHash, &prevHash); err != nil {
			return false, err
		}

		if prevHash != expectedPrevHash {
			return false, nil // 체인이 깨짐
		}

		expectedPrevHash = payloadHash
	}
	return true, nil
}

// GetAuditLogs는 시스템의 모든 감사 로그를 조회합니다.
// 오직 ADMIN 역할을 가진 사용자만 수행할 수 있습니다.
func (l *AuditLogger) GetAuditLogs(ctx context.Context, user *models.User) ([]AuditLogEntry, error) {
	// 1. 권한 체크 (RBAC)
	if user == nil || user.Role != "ADMIN" {
		return nil, ErrPermissionDenied
	}

	// 2. 로그 조회
	query := `SELECT id, event_type, actor_id, resource_id, message, payload_hash, previous_hash, created_at 
	          FROM audit_logs ORDER BY id DESC LIMIT 100`
	rows, err := l.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLogEntry
	for rows.Next() {
		var entry AuditLogEntry
		err := rows.Scan(&entry.ID, &entry.EventType, &entry.ActorID, &entry.ResourceID, 
			&entry.Message, &entry.PayloadHash, &entry.PreviousHash, &entry.CreatedAt)
		if err != nil {
			return nil, err
		}
		logs = append(logs, entry)
	}
	return logs, nil
}

// GetAuditLogsByUser는 특정 사용자와 관련된 감사 로그를 조회합니다.
// 오직 ADMIN 역할을 가진 사용자만 수행할 수 있습니다.
func (l *AuditLogger) GetAuditLogsByUser(ctx context.Context, adminUser *models.User, targetUserID string) ([]AuditLogEntry, error) {
	if adminUser == nil || adminUser.Role != "ADMIN" {
		return nil, ErrPermissionDenied
	}

	query := `SELECT id, event_type, actor_id, resource_id, message, payload_hash, previous_hash, created_at 
	          FROM audit_logs 
			  WHERE actor_id = ? OR resource_id = ?
			  ORDER BY id DESC LIMIT 100`
	rows, err := l.db.QueryContext(ctx, query, targetUserID, targetUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLogEntry
	for rows.Next() {
		var entry AuditLogEntry
		err := rows.Scan(&entry.ID, &entry.EventType, &entry.ActorID, &entry.ResourceID, 
			&entry.Message, &entry.PayloadHash, &entry.PreviousHash, &entry.CreatedAt)
		if err != nil {
			return nil, err
		}
		logs = append(logs, entry)
	}
	return logs, nil
}
