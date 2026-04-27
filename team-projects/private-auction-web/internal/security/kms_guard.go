package security

import (
	"context"
	"fmt"
	"time"
)

// KMSGuard는 마스터 키(Root KEK)에 대한 접근 정책을 집행하는 가상 보안 모듈입니다.
// 실제 환경에서는 AWS KMS, HashiCorp Vault 또는 물리적 HSM의 정책으로 구현됩니다.
type KMSGuard struct {
	MasterKEK        []byte
	RequiredApprovals int // 해제를 위해 필요한 관리자 승인 최소 수 (Quorum)
}

// ApprovalToken은 특정 리소스 해제를 위해 관리자가 디지털 서명한 증서입니다.
type ApprovalToken struct {
	AdminID   string
	ResourceID string    // 여기서는 Auction ID
	Signature []byte    // 관리자의 개인키로 서명된 (ResourceID + Timestamp)
	Timestamp time.Time
}

// NewKMSGuard는 설정된 정책을 기반으로 KMSGuard를 생성합니다.
func NewKMSGuard(masterKEK []byte, requiredApprovals int) *KMSGuard {
	return &KMSGuard{
		MasterKEK:        masterKEK,
		RequiredApprovals: requiredApprovals,
	}
}

// UnwrapPrivateKeyWithPolicy는 시간 정책과 다중 승인 정책을 모두 검증한 후 키 봉인을 해제합니다.
func (g *KMSGuard) UnwrapPrivateKeyWithPolicy(ctx context.Context, encryptedKey []byte, auctionEndTime time.Time, tokens []ApprovalToken, adminPublicKeys map[string]string) ([]byte, error) {
	// 1. [시간 정책] 마감 시간 이전에는 어떤 경우에도 복호화 불가 (UTC 기준 엄격 비교)
	now := time.Now().UTC()
	endTimeUTC := auctionEndTime.UTC()

	if now.Before(endTimeUTC) {
		return nil, fmt.Errorf("KMS POLICY REJECTION: AUCTION NOT ENDED (NOW: %s, END: %s)", now.Format(time.RFC3339), endTimeUTC.Format(time.RFC3339))
	}

	// 2. [다중 승인 정책] 유효한 승인 토큰 검증
	validApprovals := make(map[string]bool)

	for _, token := range tokens {
		// 토큰 유효 기간 검증 (발급 후 1시간 이내만 인정)
		if now.Sub(token.Timestamp.UTC()) > 1*time.Hour {
			continue
		}

		// 해당 관리자의 공개키 로드
		pubKeyPEM, ok := adminPublicKeys[token.AdminID]
		if !ok {
			continue // 등록되지 않은 관리자
		}
		pubKey, err := LoadEd25519PublicKey(pubKeyPEM)
		if err != nil {
			continue
		}

		// 서명 검증 대상 페이로드 생성 (ResourceID + Timestamp)
		// 주의: Timestamp는 서명 시와 동일한 포맷(RFC3339)이어야 함
		payload := fmt.Sprintf("APPROVE:%s:%s", token.ResourceID, token.Timestamp.Format(time.RFC3339))
		
		if VerifySignature(pubKey, []byte(payload), token.Signature) {
			validApprovals[token.AdminID] = true
		}
	}

	if len(validApprovals) < g.RequiredApprovals {
		return nil, fmt.Errorf("KMS POLICY REJECTION: INSUFFICIENT VALID APPROVALS (GOT: %d, NEED: %d)", len(validApprovals), g.RequiredApprovals)
	}

	// 3. 모든 정책이 통과되었을 때만 Root KEK를 사용하여 실제 복호화 수행
	return UnwrapKey(g.MasterKEK, encryptedKey)
}

// Design Memo:
// 이 가상 KMS는 서버 메모리에 Root KEK를 들고 있는 것으로 묘사되지만, 
// 실제 보안 강화를 위해서는 서버가 직접 KEK를 알 수 없고 KMS API에 
// '조건부 복호화 요청(Conditional Decrypt Request)'을 보내는 방식으로 연동해야 합니다.
