package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// HashString 은 데이터를 단순히 SHA-256으로 해싱합니다. (Commitment용)
func HashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// GenerateCommitment는 입찰가, 난수, 사용자 정보를 묶어 커밋 해시를 생성합니다.
func GenerateCommitment(price int, nonce string, userID string) string {
	payload := fmt.Sprintf("%d:%d:%s:%d:%s", price, len(nonce), nonce, len(userID), userID)
	return HashString(payload)
}

// HashPassword 비밀번호와 솔트, 서버 페퍼를 조합하여 Argon2id로 해싱합니다.
func HashPassword(password string, salt []byte) string {
	// security config의 설정값(iterations, memory 등) 활용
	// 이 함수는 'AuthService' 및 'VerificationService' 등에서 공통으로 사용됩니다.
	hash := argon2.IDKey(
		[]byte(password+ServerPepper),
		salt,
		Argon2Iterations,
		Argon2Memory,
		Argon2Parallelism,
		Argon2KeyLength,
	)
	return hex.EncodeToString(hash)
}

// VerifyPassword 저장된 해시와 입력된 비밀번호를 안전하게(Constant-time) 비교합니다.
func VerifyPassword(password string, salt []byte, storedHashHex string) bool {
	// 1. 입력받은 비밀번호를 동일하게 해싱
	inputHashHex := HashPassword(password, salt)

	// 2. 16진수 문자열을 바이트 슬라이스로 복원
	inputHash, err1 := hex.DecodeString(inputHashHex)
	storedHash, err2 := hex.DecodeString(storedHashHex)

	if err1 != nil || err2 != nil {
		return false
	}

	// 3. ConstantTimeCompare로 타이밍 공격 방지하며 비교
	if len(inputHash) != len(storedHash) {
		return false
	}
	return subtle.ConstantTimeCompare(inputHash, storedHash) == 1
}
