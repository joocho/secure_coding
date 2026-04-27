package security

import "blind-auction-go/pkg/models"

// RBACService는 역할 기반 접근 제어를 관리합니다.
type RBACService struct {
	// 향후 확장 시 필요한 설정값 (예: 권한 맵)
}

// 가능범위 검증함
func (s *RBACService) HasPermission(userRole models.Role, action string) bool {
	if userRole == models.RoleAdmin {
		return true
	}
	return false
}

// CheckRole은 사용자의 역할이 요구되는 역할과 >>일치<<하거나 상위 권한인지 확인합니다.
func CheckRole(userRole models.Role, requiredRole models.Role) bool {
	// 1. 관리자(ADMIN)는 모든 권한을 통과합니다.
	if userRole == models.RoleAdmin {
		return true
	}

	// 2. GUEST는 관리자 제외하고는 어떤 요구 역할도 통과하지 못합니다. (읽기 전용)
	if userRole == models.RoleGuest {
		return false
	}

	// 3. 역할이 정확히 일치하는지 확인합니다.
	return userRole == requiredRole
}

// CanAccessAuctionPhase는 경매의 현재 단계(Phase)에 따라 허용되는 행위인지 검증합니다.
func CanAccessAuctionPhase(role models.Role, currentPhase string, action string) bool {
	//추가 권한 없는 사용자의 경우
	// GUEST는 어떤 수정 액션도 불가능합니다 (read-only).
	if role == models.RoleGuest {
		// "view" 같은 액션은 허용할 수 있음 (명시적으로 allow하는 경우)
		if action == "commit" || action == "reveal" || action == "create" || action == "close" {
			return false
		}
	}

	// 예: 경매가 'REVEAL' 단계가 아닐 때 공개(reveal) 시도 시 차단
	if action == "reveal" && currentPhase != "REVEAL_STAGE" {
		return false
	}

	// 예: 경매가 'OPEN' 단계일 때만 입찰(commit) 가능
	if action == "commit" && currentPhase != "OPEN" {
		return false
	}

	return true
}
