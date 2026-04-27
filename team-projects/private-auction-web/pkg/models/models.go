package models

import "time"

// Auction은 경매 정보를 나타냅니다.
type Auction struct {
	ID                  string    `json:"id"`
	Title               string    `json:"title"`
	CreatedBy           string    `json:"created_by"`
	Status              string    `json:"status"`
	PublicKey           string    `json:"public_key"`
	EncryptedPrivateKey []byte    `json:"-"`
	KEKVersion          int       `json:"kek_version"` // KEK 로테이션 지원
	StartAt             time.Time `json:"start_at"`
	EndAt               time.Time `json:"end_at"`
	CreatedAt           time.Time `json:"created_at"`
}

// Bid는 입찰 정보를 나타냅니다. (Double-Gate: 암호화 + 커미트먼트)
type Bid struct {
	ID            string    `json:"id"`
	AuctionID     string    `json:"auction_id"`
	UserID        string    `json:"user_id"`
	Version       int       `json:"version"`         // 입찰 버전 (예: 1, 2, 3...)
	ParentBidID   string    `json:"parent_bid_id"`  // 이전 버전 입찰의 ID
	Status        string    `json:"status"`          // ACTIVE, DEPRECATED (부모 입찰은 DEPRECATED 처리)
	EncryptedDEK  []byte    `json:"encrypted_dek"`  // RSA-OAEP로 암호화된 AES 키 (Envelope Encryption)
	CiphertextBid []byte    `json:"ciphertext_bid"` // AES-GCM으로 암호화된 입찰가
	Nonce         string    `json:"nonce"`          // 랜덤 논스 (부인 방지 및 솔트용)
	CommitHash    string    `json:"commit_hash"`    // Double-Gate: 사용자 측에서 생성한 해시 약속
	Signature     []byte    `json:"signature"`      // 사용자 개인키로 서명된 페이로드 (부인 방지)
	RevealedPrice *int      `json:"revealed_price,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Receipt는 서버가 입찰을 정상 수신했음을 보증하는 디지털 영수증입니다.
type Receipt struct {
	BidID           string    `json:"bid_id"`
	AuctionID       string    `json:"auction_id"`
	UserID          string    `json:"user_id"`
	CommitHash      string    `json:"commit_hash"`      // 입찰의 고유 해시
	Timestamp       time.Time `json:"timestamp"`        // 서버 수신 시간
	ServerSignature []byte    `json:"server_signature"` // 서버의 개인키로 생성된 영수증 서명
}

