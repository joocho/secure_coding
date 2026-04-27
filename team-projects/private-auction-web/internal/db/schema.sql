-- 사용자의 서명 검증을 위한 공개키 및 로그인 정보를 포함하는 테이블
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,      -- Argon2id 해시
    salt BLOB NOT NULL,               -- Argon2id 솔트
    public_key TEXT,                  -- 서명 검증용 사용자의 Ed25519 공개키
    fingerprint TEXT,                 -- 공개키 지문 (SHA-256 hex)
    role TEXT NOT NULL CHECK (role IN ('BIDDER', 'AUCTIONEER', 'ADMIN', 'GUEST')),
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    last_login_at DATETIME,
    last_failed_at DATETIME,
    is_banned INTEGER DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 경매 정보 및 키 관리 (봉투 암호화)
CREATE TABLE IF NOT EXISTS auctions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    created_by TEXT NOT NULL,
    public_key TEXT NOT NULL,         -- 경매용 RSA-4096 공개키 (PEM)
    encrypted_private_key BLOB,       -- KMS(Root KEK)로 암호화된 경매 개인키
    kek_version INTEGER NOT NULL DEFAULT 1, -- 사용된 KEK 버전
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'CLOSED', 'REVEALED')) DEFAULT 'OPEN',
    start_at DATETIME NOT NULL,
    end_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users (id)
);

-- 암호화된 입찰 데이터 및 서명 저장 (Append-only 버전 관리)
CREATE TABLE IF NOT EXISTS bids (
    id TEXT PRIMARY KEY,
    auction_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,    -- 입찰 버전 (1, 2, 3...)
    parent_bid_id TEXT,                    -- 이전 버전 입찰의 ID (Traceability)
    status TEXT NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE, DEPRECATED
    encrypted_dek BLOB NOT NULL,          -- 서버 RSA 공개키로 암호화된 AES 대칭키
    ciphertext_bid BLOB NOT NULL,         -- AES-GCM으로 암호화된 실제 입찰 금액
    nonce TEXT NOT NULL,                  -- AES-GCM IV 겸 해시 솔트 (Base64)
    commit_hash TEXT NOT NULL,            -- SHA-256(Price + Nonce + UserID)
    signature BLOB NOT NULL,              -- 전체 데이터에 대한 사용자의 디지털 서명
    revealed_price INTEGER,               -- 마감 후 복호화 및 검증된 실제 입찰 가격
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (auction_id) REFERENCES auctions (id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (parent_bid_id) REFERENCES bids (id)
);

-- 입찰 조회 성능 향상을 위한 인덱스 (사용자별 최신 입찰 추적)
CREATE INDEX IF NOT EXISTS idx_bids_latest ON bids (auction_id, user_id, version DESC);

-- 서버가 발행한 입찰 수신 영수증
CREATE TABLE IF NOT EXISTS receipts (
    bid_id TEXT PRIMARY KEY,
    auction_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    commit_hash TEXT NOT NULL,
    server_signature BLOB NOT NULL,        -- 서버의 개인키로 서명된 영수증
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bid_id) REFERENCES bids (id)
);


-- 감사 로그 (무결성 및 추적성)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,         -- KEY_GEN, BID_SUBMIT, KEY_UNWRAP, RESULT_REVEAL
    actor_id TEXT,
    resource_id TEXT,
    message TEXT,                     -- 이벤트 상세 메시지
    payload_hash TEXT,                -- 이벤트 데이터의 해시
    previous_hash TEXT,               -- 로그 연쇄(Hash Chaining)용 이전 로그 해시
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 세션 관리 테이블
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- 화이트리스트 사용자 관리 (회원가입 전 역할 부여용)
CREATE TABLE IF NOT EXISTS whitelist_users (
    username TEXT PRIMARY KEY,
    assigned_role TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- 관리자 다중 승인을 위한 토큰 저장 테이블
CREATE TABLE IF NOT EXISTS approval_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    auction_id TEXT NOT NULL,
    admin_id TEXT NOT NULL,
    signature BLOB NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(auction_id, admin_id),
    FOREIGN KEY (auction_id) REFERENCES auctions (id),
    FOREIGN KEY (admin_id) REFERENCES users (id)
);
