package security

// Argon2id 설정 상수 (OWASP 권장 가이드라인 준수)
const (
	Argon2Iterations  = 3
	Argon2Memory      = 64 * 1024 // 64MB
	Argon2Parallelism = 2
	Argon2KeyLength   = 32
	Argon2SaltLength  = 16
	ServerPepper      = "secure-default-pepper-for-blind-auction" // 운영 시 환경변수 권장
)

// --- 승인된 암호화 알고리즘 리스트 (Security Policy v1) ---
// 이 섹션은 시스템에서 허용하는 암호화 표준을 명시합니다.
// 모든 보안 로직은 아래 명시된 현대적이고 강력한 알고리즘을 기반으로 합니다.
const (
	// SymmetricEncryption: 입찰 데이터 및 키 봉인에 사용 (AES-GCM-256)
	ApprovedSymmetricAlgo = "AES-GCM-256"

	// AsymmetricEncryption: 개인키 전달 및 공개키 암호화에 사용 (RSA-OAEP-4096)
	ApprovedAsymmetricAlgo = "RSA-OAEP-4096"

	// DigitalSignature: 영수증 서명 및 관리자 승인에 사용 (Ed25519)
	ApprovedSignatureAlgo = "Ed25519"

	// HashAlgorithm: 데이터 무결성 검증 및 지문 생성에 사용 (SHA-256)
	ApprovedHashAlgo = "SHA-256"

	// KeyDerivation: 마스터 비밀번호로부터 키 유도 시 사용 (PBKDF2-SHA256)
	ApprovedKDFAlgo = "PBKDF2-SHA256"
	PBKDF2Iterations = 4096
)
