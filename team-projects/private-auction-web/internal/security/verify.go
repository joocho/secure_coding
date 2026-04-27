package security

import (
	"crypto/subtle"
	"encoding/hex"
)

// VerifyCommit은 저장된 해시(storedHash)와 사용자가 새로 제출한 입찰 정보를 대조하여 무결성을 검증합니다.
// 보안 포인트: subtle.ConstantTimeCompare를 사용하여 타이밍 공격(Timing Attack)을 원천 차단합니다.
func VerifyCommit(storedHash string, price int, salt string, userID string, auctionID string) bool {
	// 1. 사용자가 제출한 원본 데이터들로 다시 해시를 생성합니다.
	// (참고: float64 대신 정수형인 int를 사용하는 것이 금액 계산 시 오차 방지에 유리합니다.)
	expectedHashStr := CreateBidCommit(price, salt, userID, auctionID)

	// 2. 비교를 위해 16진수 문자열을 바이트 슬라이스로 변환합니다.
	actualBytes, err1 := hex.DecodeString(storedHash)
	expectedBytes, err2 := hex.DecodeString(expectedHashStr)

	// 변환 실패 시(잘못된 해시 형식 등) 바로 거부
	if err1 != nil || err2 != nil {
		return false
	}

	// 3. 두 바이트 슬라이스의 길이가 다르면 즉시 거부
	if len(actualBytes) != len(expectedBytes) {
		return false
	}

	// 4. [핵심 보안] 상수 시간 비교 수행 (일치하면 1, 다르면 0 반환)
	// 이 함수는 값이 틀려도 끝까지 모든 비트를 비교하므로 연산 시간이 동일합니다.
	return subtle.ConstantTimeCompare(actualBytes, expectedBytes) == 1
}
