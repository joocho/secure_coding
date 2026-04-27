package bid

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"blind-auction-go/internal/db"
	"blind-auction-go/internal/log"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/models"
	appErrors "blind-auction-go/pkg/errors"

	"github.com/google/uuid"
)

// Service는 입찰 관련 비즈니스 로직을 처리합니다.
type Service struct {
	db       *sql.DB
	bidStore *db.BidStore
	audit    *security.AuditLogger
}

// NewService는 BidService를 생성합니다.
func NewService(dbConn *sql.DB, audit *security.AuditLogger) *Service {
	return &Service{
		db:       dbConn,
		bidStore: db.NewBidStore(dbConn),
		audit:    audit,
	}
}

// SubmitBid는 보안 명세 v2에 따른 입찰 제출을 처리하고 디지털 영수증을 발급합니다.
func (s *Service) SubmitBid(userID, auctionID string, encryptedDEK, ciphertextBid []byte, nonce, commitHash string, signature []byte) (*models.Receipt, error) {
	ctx := context.Background()

	// 0. OWASP 기반 입력값 검증 (Strict Whitelist)
	if !security.ValidateInput(userID, 1, 64) || !security.ValidateInput(auctionID, 1, 64) {
		return nil, appErrors.ErrInvalidInput
	}
	if !security.ValidateHash(commitHash) || security.ContainsDangerousChars(nonce) {
		return nil, appErrors.ErrInvalidInput
	}
	// 바이트 슬라이스 길이 검증 (기본적인 범위 체크)
	if len(encryptedDEK) == 0 || len(ciphertextBid) == 0 || len(signature) == 0 {
		return nil, appErrors.ErrInvalidInput
	}

	// 1. 사용자 공개키 조회 및 서명 검증 (기존 Stateless Auth 유지)
	var pubKeyHex string
	err := s.db.QueryRow("SELECT public_key FROM users WHERE id = ?", userID).Scan(&pubKeyHex)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, appErrors.ErrAuthInvalid
		}
		return nil, appErrors.ErrSystemError
	}

	pubKey, err := security.LoadEd25519PublicKey(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid user public key")
	}

	// Double-Gate 검증: 암호문과 커미트먼트가 포함된 페이로드 서명 확인
	signedPayload := fmt.Sprintf("%s:%x:%x:%s", auctionID, encryptedDEK, ciphertextBid, commitHash)
	if !security.VerifySignature(pubKey, []byte(signedPayload), signature) {
		_ = s.audit.LogEvent(ctx, "BID_AUTH_FAIL", "FAILURE", userID, auctionID, "Invalid digital signature")
		return nil, appErrors.ErrAuthInvalid
	}

	// 2. 경매 상태 및 중복 입찰 확인
	var status string
	var endAtStr string
	err = s.db.QueryRow("SELECT status, end_at FROM auctions WHERE id = ?", auctionID).Scan(&status, &endAtStr)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	if status != "OPEN" {
		return nil, appErrors.ErrBidPeriodClosed
	}
	// 종료 시간 검증: DB에 OPEN으로 남아 있어도 end_at이 지났으면 입찰 거부
	if endAt, parseErr := time.Parse(time.RFC3339, endAtStr); parseErr == nil {
		if time.Now().UTC().After(endAt.UTC()) {
			_ = s.audit.LogEvent(ctx, "BID_EXPIRED", "FAILURE", userID, auctionID, "Bid rejected: auction end time has passed")
			return nil, appErrors.ErrBidPeriodClosed
		}
	}

	// 중복 입찰 확인: 이미 ACTIVE 상태인 입찰이 있는지 체크
	var existingCount int
	err = s.db.QueryRow("SELECT COUNT(*) FROM bids WHERE auction_id = ? AND user_id = ? AND status = 'ACTIVE'", auctionID, userID).Scan(&existingCount)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	if existingCount > 0 {
		return nil, appErrors.ErrDuplicateBid
	}

	// 3. 입찰 객체 생성 및 서버 영수증 서명
	bidID := uuid.NewString()
	bid := &models.Bid{
		ID:            bidID,
		AuctionID:     auctionID,
		UserID:        userID,
		EncryptedDEK:  encryptedDEK,
		CiphertextBid: ciphertextBid,
		Nonce:         nonce,
		CommitHash:    commitHash,
		Signature:     signature,
	}

	// Receipt 생성: 서버의 개인키로 입찰 수신을 확약함
	serverPriv, err := security.GetServerPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("server signing key unavailable")
	}

	receiptPayload := fmt.Sprintf("RECEIPT:%s:%s:%s", bidID, auctionID, commitHash)
	serverSig := security.SignMessage(serverPriv, []byte(receiptPayload))

	receipt := &models.Receipt{
		BidID:           bidID,
		AuctionID:       auctionID,
		UserID:          userID,
		CommitHash:      commitHash,
		ServerSignature: serverSig,
		Timestamp:       time.Now().UTC(),
	}

	// 4. DB 저장 (Append-only & Versioning)
	err = s.bidStore.CreateBidWithAudit(ctx, bid, receipt)
	if err != nil {
		log.Error("BID_STORE_FAIL", auctionID, userID, "", err.Error(), "ERR_DB_002")
		return nil, appErrors.ErrSystemError
	}

	// 5. 감사 로그 기록 (bid.Version은 CreateBidWithAudit 내에서 업데이트됨)
	_ = s.audit.LogEvent(ctx, "BID_SUBMITTED", "SUCCESS", userID, auctionID, fmt.Sprintf("Bid v%d recorded and receipt issued (BidID: %s)", bid.Version, bidID))

	return receipt, nil
}

