package middleware

import (
	//"blind-auction-go/internal/log"
	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/errors"
)

// ValidateCommitRequest는 입찰 Commit 요청을 검증합니다.
func ValidateCommitRequest(hash string) error {
	// 해시 형식 검증 (64자리 hex)
	if !security.ValidateHash(hash) {
		return errors.ErrInvalidHashFmt
	}

	// 특수문자 필터링
	if security.ContainsDangerousChars(hash) {
		return errors.ErrInvalidHashFmt
	}

	return nil
}

// ValidateRevealRequest는 입찰 Reveal 요청을 검증합니다.
func ValidateRevealRequest(price int, salt string) error {
	// 가격 유효성 검증
	if price < 0 {
		return errors.ErrInvalidPrice
	}

	// Salt 형식 검증 (hex string)
	if !security.ValidateHash(salt) && len(salt) < 32 {
		return errors.ErrInvalidHashFmt
	}

	// 특수문자 필터링
	if security.ContainsDangerousChars(salt) {
		return errors.ErrInvalidHashFmt
	}

	return nil
}

// RateLimiter는 요청 횟수를 제한합니다. (스텁)
type RateLimiter struct {
	// TODO: 구현
}

// CheckRateLimit는 사용자의 요청 횟수를 확인합니다.
func (rl *RateLimiter) CheckRateLimit(userID string) error {
	// TODO: 1분 내 10회 이상 요청 시 ERR_RATE_001 반환
	// log.Warn("RATE_LIMIT_HIT", "", userID, "", "요청 횟수 초과", "ERR_RATE_001")
	return nil
}
