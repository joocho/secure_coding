package security

import (
	"blind-auction-go/internal/log"
	"blind-auction-go/pkg/models"
	"fmt"
	"sync"
	"time"
)

var (
	// userRateMap은 사용자 ID별 마지막 요청 시간을 추적합니다.
	userRateMap = make(map[string][]time.Time)
	rateMu      sync.Mutex
)

// RateLimitGuard는 특정 사용자가 초당 요청 횟수(5회)를 초과했는지 검증합니다.
func RateLimitGuard(userID string) error {
	rateMu.Lock()
	defer rateMu.Unlock()

	now := time.Now()
	window := 1 * time.Second
	maxRequests := 5

	// 현재 시간 기준 1초 이내의 요청만 필터링
	requests := userRateMap[userID]
	var validRequests []time.Time
	for _, t := range requests {
		if now.Sub(t) <= window {
			validRequests = append(validRequests, t)
		}
	}

	if len(validRequests) >= maxRequests {
		return fmt.Errorf("security: too many requests (rate limit exceeded)")
	}

	// 새로운 요청 기록 추가
	userRateMap[userID] = append(validRequests, now)
	return nil
}

// SecurityGuard는 모든 요청의 인입 지점에서 보안 요건(인증, 권한, 입력값)을 통합 검증합니다.
func SecurityGuard(sessionUserID string, sessionRole models.Role, input string, requiredRole models.Role) (string, error) { //models.Role 타입 사용
	// 0. 속도 제한 검사 (Rate Limiting) - 무차별 연타 방지
	if err := RateLimitGuard(sessionUserID); err != nil {
		log.Warn("RATE_LIMIT_EXCEEDED", "", sessionUserID, "", "과도한 요청 감지: "+sessionUserID, "ERR_SEC_004")
		return "", err
	}

	// 1. 입력값 검증 (Validation) - 선 검증 후 정제 원칙

	// 원본 입력값에 위험한 문자가 포함되어 있는지 먼저 확인합니다.
	if ContainsDangerousChars(input) {
		log.Warn("SECURITY_GUARD_REJECTED", "", sessionUserID, "", "위험한 특수문자 포함 입력 감지: "+input, "ERR_SEC_003")
		return "", fmt.Errorf("security: dangerous input detected")
	}

	// 2. 입력값 정제 및 형식 검증 (Sanitization & Validation)
	cleanInput := SanitizeInput(input)
	if !ValidateInput(cleanInput, 1, 1000) {
		log.Warn("SECURITY_GUARD_REJECTED", "", sessionUserID, "", "유효하지 않은 입력값 형식: "+input, "ERR_SEC_001")
		return "", fmt.Errorf("security: invalid input format")
	}

	// 3. 권한 검증 (RBAC)
	if !CheckRole(sessionRole, requiredRole) {
		log.Audit("UNAUTHORIZED_ACCESS_ATTEMPT", "", sessionUserID, "",
			fmt.Sprintf("권한 부족 접근 시도: %s (필요: %s)", sessionRole, requiredRole))
		return "", fmt.Errorf("security: unauthorized access")
	}

	return cleanInput, nil
}

// PhaseGuard는 특정 액션이 현재 경매 단계에서 허용되는지 추가 검증합니다.
func PhaseGuard(sessionUserID string, role models.Role, currentPhase string, action string) error {
	if !CanAccessAuctionPhase(role, currentPhase, action) {
		log.Warn("PHASE_ACCESS_DENIED", "", sessionUserID, "",
			fmt.Sprintf("잘못된 경매 단계 접근: Phase=%s, Action=%s", currentPhase, action), "ERR_SEC_002")
		return fmt.Errorf("security: action '%s' is not allowed in phase '%s'", action, currentPhase)
	}
	return nil
}
