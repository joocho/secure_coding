package security

import (
	"testing"
)

// 1. 비밀번호 해싱 및 검증 테스트
func TestPasswordSecurity(t *testing.T) {
	password := "mySecret123!"
	salt, _ := GenerateDefaultSaltBytes() // 설정값(Argon2SaltLength)에 따라 생성

	// 해시 생성 (보안 패키지의 해싱 엔진 테스트)
	hash := HashPassword(password, salt)

	// 만약 해시가 평문 비밀번호와 같다면 보안 실패!
	if hash == password {
		t.Error("보안 오류: 비밀번호가 암호화되지 않았습니다.")
	}

	// [연동 핵심] VerifyPassword 검증 테스트
	if !VerifyPassword(password, salt, hash) {
		t.Error("검증 오류: 올바른 비밀번호인데 인증에 실패했습니다.")
	}

	// 잘못된 비밀번호 시도
	if VerifyPassword("wrong_password", salt, hash) {
		t.Error("보안 취약점: 틀린 비밀번호가 인증을 통과했습니다!")
	}
}

// 2. 입찰 봉인(Commit) 및 무결성 테스트 (SHA-256 기반)
func TestBidCommitment(t *testing.T) {
	price := 10000
	salt := "random-bid-salt"
	userID := "userA"
	auctionID := "auc_001"

	// 봉인 생성 (HashString 기반 연동)
	storedHash := CreateBidCommit(price, salt, userID, auctionID)

	// 시나리오 A: 올바른 값으로 검증했을 때 (성공해야 함)
	if !VerifyCommit(storedHash, price, salt, userID, auctionID) {
		t.Error("검증 오류: 올바른 입찰 정보인데 검증에 실패했습니다.")
	}

	// 시나리오 B: 해커가 가격을 1원이라도 조작했을 때 (실패해야 함)
	if VerifyCommit(storedHash, 10001, salt, userID, auctionID) {
		t.Error("보안 취약점: 조작된 가격이 검증을 통과했습니다!")
	}
}

// 3. 입력 방어막(InputGuard) 테스트
func TestInputGuard(t *testing.T) {
	// 정상 입력
	if !ValidateInput("user123", 4, 20) {
		t.Error("검증 오류: 정상적인 아이디가 거부되었습니다.")
	}

	// 너무 짧은 입력 (Boundary Test)
	if ValidateInput("abc", 4, 20) {
		t.Error("보안 오류: 너무 짧은 아이디가 허용되었습니다.")
	}

	// 특수문자 공격 테스트 (Security Filter)
	if ValidateInput("admin'; DROP TABLE users;--", 4, 50) {
		t.Error("보안 취약점: SQL 인젝션 위험 문자가 허용되었습니다.")
	}
}
