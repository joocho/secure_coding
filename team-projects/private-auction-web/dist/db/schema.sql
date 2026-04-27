-- 사용자의 서명 검증을 위한 공개키 및 로그인 정보를 포함하는 테이블
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,      -- Argon2id 해시
    salt BLOB NOT NULL,               -- Argon2id 솔트
    public_key TEXT,                  -- 서명 검증용 사용자의 Ed25519 공개키
    role TEXT NOT NULL CHECK (role IN ('BIDDER', 'AUCTIONEER', 'ADMIN', 'GUEST')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 경매 정보 및 키 관리 (봉투 암호화)
CREATE TABLE IF NOT EXISTS auctions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    created_by TEXT NOT NULL,
    public_key TEXT NOT NULL,         -- 경매용 RSA-4096 공개키 (PEM)
    encrypted_private_key BLOB,       -- KMS(Root KEK)로 암호화된 경매 개인키
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'CLOSED', 'REVEALED')) DEFAULT 'OPEN',
    start_at DATETIME NOT NULL,
    end_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users (id)
);

-- 암호화된 입찰 데이터 및 서명 저장
CREATE TABLE IF NOT EXISTS bids (
    id TEXT PRIMARY KEY,
    auction_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    encrypted_payload BLOB NOT NULL,  -- RSA-OAEP로 암호화된 {price, nonce, user_id}
    signature BLOB NOT NULL,          -- encrypted_payload에 대한 사용자의 디지털 서명
    revealed_price INTEGER,           -- 마감 후 복호화된 가격 (검증용)
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (auction_id) REFERENCES auctions (id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE (auction_id, user_id)
);

-- 감사 로그 (무결성 및 추적성)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,         -- KEY_GEN, BID_SUBMIT, KEY_UNWRAP, RESULT_REVEAL
    actor_id TEXT,
    resource_id TEXT,
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

-- 로그인 기록 및 계정 잠금 관리
CREATE TABLE IF NOT EXISTS login_history (
    user_id TEXT PRIMARY KEY,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    last_success_at DATETIME,
    last_failed_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- 화이트리스트 사용자 관리 (회원가입 전 역할 부여용)
CREATE TABLE IF NOT EXISTS whitelist_users (
    username TEXT PRIMARY KEY,
    assigned_role TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
