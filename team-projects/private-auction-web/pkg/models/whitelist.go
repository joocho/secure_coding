// new  화이트리스트 기반 권한 체크

package models

import "time"

// WhitelistUser는 ADMIN이 사전에 권한을 부여한 사용자 목록입니다.
type WhitelistUser struct {
	Username     string // 로그인 식별자 (PK)
	AssignedRole Role   // BIDDER | AUCTIONEER | ADMIN
	CreatedAt    time.Time
}
