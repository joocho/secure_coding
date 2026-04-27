// Package auction은 경매 관련 비즈니스 로직을 담당합니다.
package auction

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"blind-auction-go/internal/log"
	"blind-auction-go/internal/security"
	appErrors "blind-auction-go/pkg/errors"
	"blind-auction-go/pkg/models"

	"github.com/google/uuid"
)

// Service는 경매 비즈니스 로직을 처리합니다.
type Service struct {
	db    *sql.DB
	audit *security.AuditLogger
}

// NewService는 AuctionService를 생성합니다.
func NewService(db *sql.DB, audit *security.AuditLogger) *Service {
	return &Service{db: db, audit: audit}
}

// RevealedPayload는 복호화된 입찰 데이터의 구조입니다.
type RevealedPayload struct {
	Price int    `json:"price"`
	Nonce string `json:"nonce"`
}

// ─────────────────────────────────────────────
//  1. 경매 생성
// ─────────────────────────────────────────────

// CreateAuctionInput은 경매 생성 요청 파라미터입니다.
type CreateAuctionInput struct {
	Title   string
	StartAt time.Time
	EndAt   time.Time
}

// CreateAuction은 새로운 경매를 생성합니다.
func (s *Service) CreateAuction(creatorID string, input CreateAuctionInput) (*models.Auction, error) {
	// 0. OWASP 기반 입력값 검증 및 정형화
	input.Title = security.SanitizeInput(input.Title)
	if !security.ValidateInput(creatorID, 1, 64) || security.ContainsDangerousChars(input.Title) {
		return nil, appErrors.ErrInvalidInput
	}
	if len(input.Title) < 2 || len(input.Title) > 100 {
		return nil, appErrors.ErrInvalidInput
	}

	// 1. 시간 유효성 검증
	if err := validateAuctionTimes(input.StartAt, input.EndAt); err != nil {
		return nil, err
	}

	// 2. RSA 키쌍 생성 (v2 보안 핵심)
	privPEM, pubPEM, err := security.GenerateRSAKeyPair()
	if err != nil {
		log.Error("AUCTION_KEYGEN_FAIL", "", creatorID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}
	// 생성 직후 메모리 소거 예약
	defer security.ZeroingMemory([]byte(privPEM))

	// 3. 개인키 래핑 (봉투 암호화 - KEK 버전 관리 적용)
	kekVer := security.GetLatestKEKVersion()
	currentKEK, _ := security.GetKEK(kekVer)
	wrappedPriv, err := security.WrapKey(currentKEK, []byte(privPEM))
	if err != nil {
		log.Error("AUCTION_KEYWRAP_FAIL", "", creatorID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	// 4. DB INSERT
	id := uuid.NewString()
	now := time.Now().UTC()

	const q = `
		INSERT INTO auctions (id, title, created_by, status, public_key, encrypted_private_key, kek_version, start_at, end_at, created_at)
		VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?)`

	_, err = s.db.Exec(q,
		id, input.Title, creatorID,
		pubPEM, wrappedPriv, kekVer,
		input.StartAt.UTC().Format(time.RFC3339),
		input.EndAt.UTC().Format(time.RFC3339),
		now.Format(time.RFC3339),
	)
	if err != nil {
		log.Error("AUCTION_CREATE_FAIL", id, creatorID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	_ = s.audit.LogEvent(context.Background(), "KEY_GENERATED", "SUCCESS", creatorID, id, fmt.Sprintf("RSA 4096-bit keys generated and stored (KEK v%d)", kekVer))
	_ = s.audit.LogEvent(context.Background(), "AUCTION_CREATED", "SUCCESS", creatorID, id, fmt.Sprintf("Title: %s", input.Title))

	return &models.Auction{
		ID:                  id,
		Title:               input.Title,
		CreatedBy:           creatorID,
		Status:              "OPEN",
		PublicKey:           pubPEM,
		EncryptedPrivateKey: wrappedPriv,
		KEKVersion:          kekVer,
		StartAt:             input.StartAt,
		EndAt:               input.EndAt,
		CreatedAt:           now,
	}, nil
}

// ─────────────────────────────────────────────
//  2. 경매 상태 관리
// ─────────────────────────────────────────────

// CloseAuction은 경매를 수동으로 마감 상태로 전환합니다.
func (s *Service) CloseAuction(ctx context.Context, auctionID string) error {
	auction, err := s.GetAuction(auctionID)
	if err != nil {
		return err
	}

	if auction.Status != "OPEN" {
		return &appErrors.AppError{Code: "ERR_BID_002", Message: "마감할 수 없는 상태의 경매입니다."}
	}

	const q = `UPDATE auctions SET status = 'CLOSED' WHERE id = ?`
	_, err = s.db.ExecContext(ctx, q, auctionID)
	if err != nil {
		return appErrors.ErrSystemError
	}

	_ = s.audit.LogEvent(ctx, "AUCTION_CLOSED", "SUCCESS", "SYSTEM", auctionID, "Auction status changed to CLOSED")
	return nil
}

// RevealAuctionResults는 마감된 경매의 모든 입찰가를 복호화하고 결과를 산출합니다. (보안 정책 v2 적용)
func (s *Service) RevealAuctionResults(ctx context.Context, auctionID string) error {
	// 1. 경매 및 래핑된 개인키 조회
	auction, err := s.GetAuction(auctionID)
	if err != nil {
		return err
	}

	if auction.Status != "CLOSED" {
		return &appErrors.AppError{Code: "ERR_BID_002", Message: "마감된 경매만 결과를 공개할 수 있습니다."}
	}

	// 2. [보안 정책 v2] KMSGuard 정책 검증 (시간 및 Quorum 승인)
	kek, err := security.GetKEK(auction.KEKVersion)
	if err != nil {
		return appErrors.ErrSystemError
	}
	
	// 최소 2명의 관리자 승인 필요 (Quorum: 2)
	const requiredApprovals = 2
	kms := security.NewKMSGuard(kek, requiredApprovals)
	
	// DB에서 해당 경매에 대한 승인 토큰 목록 조회
	tokens, err := s.GetApprovalTokens(auctionID)
	if err != nil {
		return appErrors.ErrSystemError
	}
	
	// 모든 관리자의 공개키 맵 구축 (검증용)
	adminPubs := make(map[string]string)
	adminRows, err := s.db.QueryContext(ctx, "SELECT id, public_key FROM users WHERE role IN ('ADMIN', 'AUCTIONEER')")
	if err != nil {
		return appErrors.ErrSystemError
	}
	defer adminRows.Close()
	for adminRows.Next() {
		var aid, apubHex string
		if err := adminRows.Scan(&aid, &apubHex); err == nil {
			// Hex 형태의 Ed25519 공개키를 PEM으로 변환하여 KMSGuard가 인식할 수 있게 함
			pubBytes, _ := hex.DecodeString(apubHex)
			adminPubs[aid] = security.ExportEd25519PublicKeyToPEM(pubBytes)
		}
	}

	// 정책 기반 개인키 Unwrap
	privPEM, err := kms.UnwrapPrivateKeyWithPolicy(ctx, auction.EncryptedPrivateKey, auction.EndAt, tokens, adminPubs)
	if err != nil {
		log.Error("KMS_POLICY_VIOLATION", auctionID, "SYSTEM", "", err.Error(), "ERR_AUTH_002")
		_ = s.audit.LogEvent(ctx, "KMS_REJECTION", "FAILURE", "SYSTEM", auctionID, "POLICY VIOLATION: "+err.Error())
		return &appErrors.AppError{Code: "ERR_AUTH_002", Message: "보안 정책에 의해 복호화가 거부되었습니다: " + err.Error()}
	}
	// 작업 완료 후 메모리 소거 보장
	defer security.ZeroingMemory(privPEM)

	// 3. 입찰 목록 조회
	rows, err := s.db.QueryContext(ctx, "SELECT id, user_id, encrypted_dek, ciphertext_bid, nonce, commit_hash, signature FROM bids WHERE auction_id = ?", auctionID)
	if err != nil {
		return appErrors.ErrSystemError
	}
	defer rows.Close()

	type bidData struct {
		id            string
		userID        string
		encryptedDEK  []byte
		ciphertextBid []byte
		nonce         string
		commitHash    string
		signature     []byte
	}
	var bids []bidData
	for rows.Next() {
		var b bidData
		if err := rows.Scan(&b.id, &b.userID, &b.encryptedDEK, &b.ciphertextBid, &b.nonce, &b.commitHash, &b.signature); err != nil {
			return appErrors.ErrSystemError
		}
		bids = append(bids, b)
	}

	// 4. 각 입찰 복호화 및 검증 (트랜잭션 처리)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return appErrors.ErrSystemError
	}
	defer tx.Rollback()

	for _, b := range bids {
		// (1) 사용자 공개키 조회 (Hex 형식)
		var pubKeyHex string
		err := tx.QueryRowContext(ctx, "SELECT public_key FROM users WHERE id = ?", b.userID).Scan(&pubKeyHex)
		if err != nil {
			continue
		}

		// (2) 공개키 Hex 디코딩
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			continue
		}

		// (3) 서명 검증 (Ed25519)
		signedPayload := fmt.Sprintf("%s:%x:%x:%s", auctionID, b.encryptedDEK, b.ciphertextBid, b.commitHash)
		if !security.VerifySignature(pubKeyBytes, []byte(signedPayload), b.signature) {
			_ = s.audit.LogEvent(ctx, "BID_VERIFY_FAIL", "FAILURE", b.userID, auctionID, "Signature mismatch during reveal")
			continue
		}

		// (4) 봉투 열기: RSA 개인키로 DEK 복호화
		dek, err := security.DecryptRSA(string(privPEM), b.encryptedDEK)
		if err != nil {
			continue
		}

		// (5) AES-GCM으로 입찰가 본문 복호화
		nonceBytes, err := base64.StdEncoding.DecodeString(b.nonce)
		if err != nil {
			continue
		}
		block, err := aes.NewCipher(dek)
		if err != nil {
			continue
		}
		aesGcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		
		decryptedPriceBytes, err := aesGcm.Open(nil, nonceBytes, b.ciphertextBid, nil)
		if err != nil {
			continue 
		}
		// 단기 대칭키 메모리 소거 예약
		defer security.ZeroingMemory(dek)

		price, err := strconv.Atoi(string(decryptedPriceBytes))
		if err != nil {
			continue
		}

		// (6) 커밋 무결성 검증 (서버가 복호화한 값으로 해시 재연산)
		expectedHash := security.GenerateCommitment(price, b.nonce, b.userID)
		if expectedHash != b.commitHash {
			_ = s.audit.LogEvent(ctx, "BID_VERIFY_FAIL", "FAILURE", b.userID, auctionID, "Commitment hash mismatch (Integrity violated)")
			continue
		}

		// 성공: 복호화된 가격 저장
		_, _ = tx.ExecContext(ctx, "UPDATE bids SET revealed_price = ? WHERE id = ?", price, b.id)
	}

	// 5. 경매 상태 변경 (REVEALED)
	_, err = tx.ExecContext(ctx, "UPDATE auctions SET status = 'REVEALED' WHERE id = ?", auctionID)
	if err != nil {
		return appErrors.ErrSystemError
	}

	if err := tx.Commit(); err != nil {
		return appErrors.ErrSystemError
	}

	_ = s.audit.LogEvent(ctx, "RESULT_REVEALED", "SUCCESS", "SYSTEM", auctionID, "All bids decrypted and verified")

	return nil
}

// ─────────────────────────────────────────────
//  3. 경매 조회
// ─────────────────────────────────────────────

func (s *Service) GetAuction(auctionID string) (*models.Auction, error) {
	const q = `
		SELECT id, title, created_by, status, public_key, encrypted_private_key, kek_version, start_at, end_at, created_at
		FROM auctions
		WHERE id = ?`

	row := s.db.QueryRow(q, auctionID)
	var a models.Auction
	var startAt, endAt, createdAt string
	err := row.Scan(&a.ID, &a.Title, &a.CreatedBy, &a.Status, &a.PublicKey, &a.EncryptedPrivateKey, &a.KEKVersion, &startAt, &endAt, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &appErrors.AppError{Code: "ERR_BID_001", Message: "존재하지 않는 경매입니다."}
		}
		return nil, appErrors.ErrSystemError
	}
	a.StartAt, _ = time.Parse(time.RFC3339, startAt)
	a.EndAt, _ = time.Parse(time.RFC3339, endAt)
	a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &a, nil
}

// ─────────────────────────────────────────────
//  4. 낙찰 결과 조회
// ─────────────────────────────────────────────

type AuctionResult struct {
	AuctionID      string     `json:"auctionId"`
	Status         string     `json:"status"`
	WinnerID       *string    `json:"winnerId"`
	WinnerUsername *string    `json:"winnerUsername"`
	WinnerPrice    *int       `json:"winnerPrice"`
	Bids           []BidEntry `json:"bids"`
}

type BidEntry struct {
	UserID     string `json:"userId"`
	Price      *int   `json:"price"`
	CommitHash string `json:"commitHash"`
}

func (s *Service) GetAuctionResult(auctionID string) (*AuctionResult, error) {
	auction, err := s.GetAuction(auctionID)
	if err != nil {
		return nil, err
	}

	if auction.Status != "REVEALED" {
		return nil, &appErrors.AppError{Code: "ERR_BID_002", Message: "결과가 아직 공개되지 않았습니다."}
	}

	// 입찰 목록 조회 (최고가 순)
	const q = `
		SELECT user_id, revealed_price, commit_hash
		FROM bids
		WHERE auction_id = ? AND revealed_price IS NOT NULL
		ORDER BY revealed_price DESC, created_at ASC`

	rows, err := s.db.Query(q, auctionID)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	defer rows.Close()

	var bids []BidEntry
	for rows.Next() {
		var e BidEntry
		if err := rows.Scan(&e.UserID, &e.Price, &e.CommitHash); err != nil {
			return nil, appErrors.ErrSystemError
		}
		bids = append(bids, e)
	}

	result := &AuctionResult{
		AuctionID: auctionID,
		Status:    auction.Status,
		Bids:      bids,
	}

	if len(bids) > 0 {
		winner := bids[0]
		result.WinnerID = &winner.UserID
		result.WinnerPrice = winner.Price

		var username string
		_ = s.db.QueryRow(`SELECT username FROM users WHERE id = ?`, winner.UserID).Scan(&username)
		result.WinnerUsername = &username
	}

	return result, nil
}

func validateAuctionTimes(startAt, endAt time.Time) error {
	if startAt.IsZero() || endAt.IsZero() {
		return &appErrors.AppError{Code: "ERR_BID_004", Message: "시작/종료 시간을 입력해주세요."}
	}
	if !endAt.After(startAt) {
		return &appErrors.AppError{Code: "ERR_BID_004", Message: "종료 시간은 시작 시간보다 이후여야 합니다."}
	}
	if !endAt.After(time.Now()) {
		return &appErrors.AppError{Code: "ERR_BID_004", Message: "종료 시간은 현재 시간보다 이후여야 합니다."}
	}
	return nil
}

// ─────────────────────────────────────────────
//  5. 경매 목록 조회
// ─────────────────────────────────────────────

// ListAuctions는 모든 경매를 생성일 역순으로 반환합니다.
// 조회 시점에 end_at이 지난 OPEN 경매는 자동으로 CLOSED 상태로 전환하며,
// 종료된 지 30일이 지난 데이터는 보안을 위해 파기(Purge)합니다.
func (s *Service) ListAuctions() ([]*models.Auction, error) {
	// 1. 만료된 OPEN 경매를 일괄 자동 마감
	if err := s.autoCloseExpiredAuctions(); err != nil {
		log.Error("AUTO_CLOSE_FAIL", "", "SYSTEM", "", err.Error(), "ERR_SYS_001")
	}

	// 2. [L11] 종료된 지 30일이 지난 데이터 영구 파기 (Purge)
	if err := s.PurgeOldData(30); err != nil {
		log.Error("PURGE_DATA_FAIL", "", "SYSTEM", "", err.Error(), "ERR_SYS_001")
	}

	const q = `SELECT id, title, created_by, status, public_key, encrypted_private_key, kek_version, start_at, end_at, created_at FROM auctions ORDER BY created_at DESC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	defer rows.Close()

	var result []*models.Auction
	for rows.Next() {
		var a models.Auction
		var startAt, endAt, createdAt string
		if err := rows.Scan(&a.ID, &a.Title, &a.CreatedBy, &a.Status, &a.PublicKey, &a.EncryptedPrivateKey, &a.KEKVersion, &startAt, &endAt, &createdAt); err != nil {
			return nil, appErrors.ErrSystemError
		}
		a.StartAt, _ = time.Parse(time.RFC3339, startAt)
		a.EndAt, _ = time.Parse(time.RFC3339, endAt)
		a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		result = append(result, &a)
	}
	return result, nil
}

// PurgeOldData는 종료된 지 days일이 지난 경매와 관련 입찰 데이터를 영구 삭제합니다.
func (s *Service) PurgeOldData(days int) error {
	// 삭제 기준 시각 계산 (현재 - 30일)
	cutoff := time.Now().AddDate(0, 0, -days).UTC().Format(time.RFC3339)

	// 1. 삭제 대상 경매 ID 조회
	rows, err := s.db.Query("SELECT id FROM auctions WHERE status IN ('CLOSED', 'REVEALED') AND end_at <= ?", cutoff)
	if err != nil {
		return err
	}
	defer rows.Close()

	var targetIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		targetIDs = append(targetIDs, id)
	}

	if len(targetIDs) == 0 {
		return nil
	}

	// 2. 트랜잭션 시작
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, id := range targetIDs {
		// 해당 경매의 모든 입찰 데이터 삭제
		_, err = tx.Exec("DELETE FROM bids WHERE auction_id = ?", id)
		if err != nil {
			return err
		}

		// 경매 자체 삭제
		_, err = tx.Exec("DELETE FROM auctions WHERE id = ?", id)
		if err != nil {
			return err
		}

		// 보안 감사 로그 기록 (마스킹 적용됨)
		_ = s.audit.LogEvent(context.Background(), "DATA_PURGED", "SUCCESS", "SYSTEM", id, 
			"보안 정책(L11)에 따라 30일이 경과된 경매 데이터를 영구 파기하였습니다.")
	}

	return tx.Commit()
}

// autoCloseExpiredAuctions는 end_at이 현재 시각보다 이전인 OPEN 경매를 CLOSED로 일괄 전환합니다.
func (s *Service) autoCloseExpiredAuctions() error {
	now := time.Now().UTC().Format(time.RFC3339)
	const q = `UPDATE auctions SET status = 'CLOSED' WHERE status = 'OPEN' AND end_at <= ?`
	res, err := s.db.Exec(q, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		_ = s.audit.LogEvent(context.Background(), "AUCTION_AUTO_CLOSED", "SUCCESS", "SYSTEM", "",
			fmt.Sprintf("%d개의 만료된 경매가 자동으로 마감 처리되었습니다.", n))
	}
	return nil
}

// RotateAuctionKey는 기존 암호화된 개인키를 최신 버전의 KEK로 다시 암호화(Re-wrap)합니다.
// 일주일 이상의 긴 경매 기간 동안 마스터 키가 바뀌었을 때 보안을 유지하기 위해 사용합니다.
func (s *Service) RotateAuctionKey(ctx context.Context, auctionID string) error {
	// 1. 기존 데이터 조회
	auction, err := s.GetAuction(auctionID)
	if err != nil {
		return err
	}

	latestVer := security.GetLatestKEKVersion()
	if auction.KEKVersion == latestVer {
		return nil // 이미 최신 버전임
	}

	// 2. 구 버전 KEK로 복호화 (Unwrap)
	oldKEK, err := security.GetKEK(auction.KEKVersion)
	if err != nil {
		return err
	}
	privPEM, err := security.UnwrapKey(oldKEK, auction.EncryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to unwrap with old KEK: %w", err)
	}
	defer security.ZeroingMemory(privPEM)

	// 3. 신 버전 KEK로 재암호화 (Wrap)
	newKEK, err := security.GetKEK(latestVer)
	if err != nil {
		return err
	}
	newWrappedPriv, err := security.WrapKey(newKEK, privPEM)
	if err != nil {
		return err
	}

	// 4. DB 업데이트
	const q = `UPDATE auctions SET encrypted_private_key = ?, kek_version = ? WHERE id = ?`
	_, err = s.db.ExecContext(ctx, q, newWrappedPriv, latestVer, auctionID)
	if err != nil {
		return appErrors.ErrSystemError
	}

	_ = s.audit.LogEvent(ctx, "KEY_ROTATED", "SUCCESS", "SYSTEM", auctionID, fmt.Sprintf("Auction key re-wrapped from KEK v%d to v%d", auction.KEKVersion, latestVer))
	
	return nil
}
// AddApprovalToken은 관리자의 승인 서명을 데이터베이스에 저장합니다.
func (s *Service) AddApprovalToken(auctionID, adminID string, signature []byte, timestamp time.Time) error {
	const q = `
		INSERT INTO approval_tokens (auction_id, admin_id, signature, timestamp)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(auction_id, admin_id) DO UPDATE SET 
			signature = excluded.signature,
			timestamp = excluded.timestamp`

	_, err := s.db.Exec(q, auctionID, adminID, signature, timestamp.Format(time.RFC3339))
	if err != nil {
		return appErrors.ErrSystemError
	}

	_ = s.audit.LogEvent(context.Background(), "ADMIN_APPROVED", "SUCCESS", adminID, auctionID, "관리자 승인 서명이 등록되었습니다.")
	return nil
}

// GetApprovalTokens는 해당 경매에 등록된 모든 관리자 승인 토큰을 반환합니다.
func (s *Service) GetApprovalTokens(auctionID string) ([]security.ApprovalToken, error) {
	const q = `SELECT admin_id, signature, timestamp FROM approval_tokens WHERE auction_id = ?`
	rows, err := s.db.Query(q, auctionID)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	defer rows.Close()

	var tokens []security.ApprovalToken
	for rows.Next() {
		var t security.ApprovalToken
		var ts string
		if err := rows.Scan(&t.AdminID, &t.Signature, &ts); err != nil {
			return nil, appErrors.ErrSystemError
		}
		t.ResourceID = auctionID
		t.Timestamp, _ = time.Parse(time.RFC3339, ts)
		tokens = append(tokens, t)
	}
	return tokens, nil
}
