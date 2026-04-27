# Submission Protocol & API Spec

## 1. User Management (사용자 등록)

### POST /users
사용자 신원을 등록하고 공개키를 제출합니다.
- **Request**:
  ```json
  {
    "username": "user1",
    "password": "...",
    "public_key": "-----BEGIN PUBLIC KEY-----..."
  }
  ```
- **Response**:
  ```json
  {
    "user_id": "uuid",
    "fingerprint": "sha256-hex-fingerprint",
    "role": "BIDDER"
  }
  ```

## 2. Auctions (경매 정보 조회)

### GET /auctions/{id}
경매 상세 정보 및 봉인용 RSA 공개키를 가져옵니다.
- **Response**:
  ```json
  {
    "auction_id": "uuid",
    "public_key": "-----BEGIN PUBLIC KEY-----...",
    "status": "OPEN",
    "end_time": "2026-04-10T00:00:00Z"
  }
  ```

## 3. Bidding (입찰 데이터 제출)

### POST /auctions/{id}/bids
Double-Gate 입찰 데이터를 제출하고 서버 서명 영수증을 받습니다.
- **Request Body**:
  ```json
  {
    "user_id": "uuid",
    "encrypted_dek": "...",     -- 서버 RSA 공개키로 암호화된 AES 키
    "ciphertext_bid": "...",    -- AES-GCM으로 암호화된 입찰가
    "nonce": "...",             -- IV 겸 커미트먼트 솔트
    "commit_hash": "...",       -- SHA-256(Price + Nonce + UserID)
    "signature": "..."          -- Sign(User_PrivKey, Payload)
  }
  ```
- **Response (Digital Receipt)**:
  ```json
  {
    "bid_id": "uuid",
    "auction_id": "uuid",
    "commit_hash": "...",
    "server_signature": "...",  -- 서버 개인키로 서명된 영수증
    "timestamp": "2026-04-10T12:00:00Z"
  }
  ```

## 4. Admin Operations (관리자 작업)

### POST /admin/approve-reveal
경매 마감 후 키 해제를 위한 관리자 승인 토큰을 생성합니다.
- **Response**:
  ```json
  {
    "admin_id": "uuid",
    "resource_id": "auction_id",
    "signature": "...",
    "timestamp": "..."
  }
  ```

### POST /auctions/{id}/reveal
마감된 경매의 결과를 공개합니다. (충분한 승인 토큰 필요)
- **Request**:
  ```json
  {
    "approval_tokens": [
      { "admin_id": "...", "signature": "...", "timestamp": "..." },
      ...
    ]
  }
  ```
