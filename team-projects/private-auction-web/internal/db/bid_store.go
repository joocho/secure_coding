package db

import (
	"context"
	"database/sql"
	"time"

	"blind-auction-go/pkg/models"
)

// BidStore는 입찰 데이터의 저장 및 이력 관리를 담당합니다. (Append-only)
type BidStore struct {
	db *sql.DB
}

// NewBidStore는 새로운 BidStore를 생성합니다.
func NewBidStore(db *sql.DB) *BidStore {
	return &BidStore{db: db}
}

// CreateBidWithAudit는 입찰 정보를 Append-only 방식으로 저장하고 영수증을 연계합니다.
// 기존에 ACTIVE 상태인 입찰이 있다면 DEPRECATED로 변경하고 버전을 올립니다.
func (s *BidStore) CreateBidWithAudit(ctx context.Context, bid *models.Bid, receipt *models.Receipt) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. 기존 최신 버전 확인 (v1 -> v2 -> v3 추적)
	var currentID string
	var currentVersion int
	query := `SELECT id, version FROM bids WHERE auction_id = ? AND user_id = ? AND status = 'ACTIVE' LIMIT 1`
	err = tx.QueryRowContext(ctx, query, bid.AuctionID, bid.UserID).Scan(&currentID, &currentVersion)

	if err == nil {
		// 기존 입찰 존재 -> 상태 전이 (ACTIVE -> DEPRECATED)
		_, err = tx.ExecContext(ctx, "UPDATE bids SET status = 'DEPRECATED' WHERE id = ?", currentID)
		if err != nil {
			return err
		}
		bid.Version = currentVersion + 1
		bid.ParentBidID = currentID
	} else if err == sql.ErrNoRows {
		// 신규 입찰
		bid.Version = 1
		bid.ParentBidID = ""
	} else {
		return err
	}

	bid.Status = "ACTIVE"
	now := time.Now().UTC()
	bid.CreatedAt = now

	// 2. 입찰 정보 저장 (절대 삭제/수정하지 않고 쌓음)
	const qBid = `
		INSERT INTO bids (
			id, auction_id, user_id, version, parent_bid_id, status,
			encrypted_dek, ciphertext_bid, nonce, commit_hash, signature, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var parentBidID any
	if bid.ParentBidID == "" {
		parentBidID = nil
	} else {
		parentBidID = bid.ParentBidID
	}

	_, err = tx.ExecContext(ctx, qBid,
		bid.ID, bid.AuctionID, bid.UserID, bid.Version, parentBidID, bid.Status,
		bid.EncryptedDEK, bid.CiphertextBid, bid.Nonce, bid.CommitHash, bid.Signature, now)
	if err != nil {
		return err
	}

	// 3. 영수증 저장
	const qReceipt = `
		INSERT INTO receipts (
			bid_id, auction_id, user_id, commit_hash, server_signature, timestamp
		) VALUES (?, ?, ?, ?, ?, ?)`

	receipt.Timestamp = now
	_, err = tx.ExecContext(ctx, qReceipt,
		bid.ID, bid.AuctionID, bid.UserID, bid.CommitHash, receipt.ServerSignature, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetLatestBid는 특정 사용자의 가장 최신 입찰 정보를 조회합니다.
func (s *BidStore) GetLatestBid(ctx context.Context, auctionID, userID string) (*models.Bid, error) {
	const q = `
		SELECT id, auction_id, user_id, version, parent_bid_id, status, 
		       encrypted_dek, ciphertext_bid, nonce, commit_hash, signature, created_at
		FROM bids 
		WHERE auction_id = ? AND user_id = ? AND status = 'ACTIVE'
		ORDER BY version DESC LIMIT 1`

	var b models.Bid
	err := s.db.QueryRowContext(ctx, q, auctionID, userID).Scan(
		&b.ID, &b.AuctionID, &b.UserID, &b.Version, &b.ParentBidID, &b.Status,
		&b.EncryptedDEK, &b.CiphertextBid, &b.Nonce, &b.CommitHash, &b.Signature, &b.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// GetBidHistory는 특정 사용자의 입찰 수정 이력을 모두 조회합니다. (Traceability)
func (s *BidStore) GetBidHistory(ctx context.Context, auctionID, userID string) ([]models.Bid, error) {
	const q = `
		SELECT id, auction_id, user_id, version, parent_bid_id, status, created_at
		FROM bids 
		WHERE auction_id = ? AND user_id = ? 
		ORDER BY version DESC`

	rows, err := s.db.QueryContext(ctx, q, auctionID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []models.Bid
	for rows.Next() {
		var b models.Bid
		if err := rows.Scan(&b.ID, &b.AuctionID, &b.UserID, &b.Version, &b.ParentBidID, &b.Status, &b.CreatedAt); err != nil {
			return nil, err
		}
		history = append(history, b)
	}
	return history, nil
}
