package main

import (
	"context"
	"fmt"
	"time"
	"blind-auction-go/internal/security"
	"crypto/ed25519"
	"crypto/rand"
)

func main() {
	fmt.Println("=== 블라인드 경매 KMS 정책 시뮬레이션 ===")

	// 1. 초기화: 마스터 키 및 가드 설정 (2-of-3 정책: 관리자 2명 이상 승인 필요)
	rootKEK := []byte("master-key-encryption-key-32-byt")
	guard := security.NewKMSGuard(rootKEK, 2)

	auctionID := "auction-uuid-1234"
	
	// 경매 암호화 데이터 (실제 데이터 대신 임시 데이터)
	// 실제로는 Auction Private Key가 Root KEK로 Wrap된 상태임.
	wrappedKey, _ := security.WrapKey(rootKEK, []byte("PRIVATE-KEY-CONTENT-PEM"))

	// 가상의 관리자들 및 공개키 등록
	admin1Pub, admin1Priv, _ := ed25519.GenerateKey(rand.Reader)
	admin2Pub, admin2Priv, _ := ed25519.GenerateKey(rand.Reader)
	
	admin1PubPEM := security.ExportEd25519PublicKeyToPEM(admin1Pub)
	admin2PubPEM := security.ExportEd25519PublicKeyToPEM(admin2Pub)

	adminPubKeys := map[string]string{
		"admin-alpha": admin1PubPEM,
		"admin-beta":  admin2PubPEM,
	}

	// --- 시나리오 1: 마감 전 복호화 시도 ---
	futureEndTime := time.Now().Add(24 * time.Hour)
	fmt.Printf("\n[시나리오 1] 경매 마감 전 (%s) 시도:\n", futureEndTime.Format(time.RFC3339))
	
	_, err := guard.UnwrapPrivateKeyWithPolicy(context.Background(), wrappedKey, futureEndTime, nil, adminPubKeys)
	fmt.Println("결과:", err) // POLICY REJECTION 예상

	// --- 시나리오 2: 마감 후, 승인 부족 (1명만 승인) ---
	pastEndTime := time.Now().Add(-1 * time.Hour)
	fmt.Printf("\n[시나리오 2] 마감 후 시도, 승인 1명:\n")
	
	ts1 := time.Now()
	payload1 := fmt.Sprintf("APPROVE:%s:%s", auctionID, ts1.Format(time.RFC3339))
	token1 := security.ApprovalToken{
		AdminID: "admin-alpha",
		ResourceID: auctionID,
		Timestamp: ts1,
		Signature: security.SignMessage(admin1Priv, []byte(payload1)), // 서명 시뮬레이션
	}
	
	_, err = guard.UnwrapPrivateKeyWithPolicy(context.Background(), wrappedKey, pastEndTime, []security.ApprovalToken{token1}, adminPubKeys)
	fmt.Println("결과:", err) // INSUFFICIENT APPROVALS 예상

	// --- 시나리오 3: 마감 후, 승인 충족 (2명 승인) ---
	fmt.Printf("\n[시나리오 3] 마감 후 시도, 승인 2명 (정상 조건):\n")
	
	ts2 := time.Now()
	payload2 := fmt.Sprintf("APPROVE:%s:%s", auctionID, ts2.Format(time.RFC3339))
	token2 := security.ApprovalToken{
		AdminID: "admin-beta",
		ResourceID: auctionID,
		Timestamp: ts2,
		Signature: security.SignMessage(admin2Priv, []byte(payload2)),
	}
	
	tokens := []security.ApprovalToken{token1, token2}
	plainKey, err := guard.UnwrapPrivateKeyWithPolicy(context.Background(), wrappedKey, pastEndTime, tokens, adminPubKeys)
	
	if err == nil {
		fmt.Println("성공! 경매 개인키가 복구되었습니다.")
		fmt.Printf("복구된 키 일부: %s...\n", string(plainKey[:12]))
	} else {
		fmt.Println("실패:", err)
	}
}
