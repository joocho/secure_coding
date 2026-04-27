package security

import (
	"fmt"
)

// CreateBidCommit은 입찰 정보를 SHA-256으로 봉인(Commitment)합니다.
// 금액(price), 솔트(salt), 사용자 ID, 경매 ID를 결합하여 데이터의 무결성과 소유권을 보장합니다.
func CreateBidCommit(price int, salt string, userID string, auctionID string) string {
	// 데이터 결속(Binding): 금액뿐만 아니라 사용자ID와 경매ID를 함께 묶어
	// 다른 사람이 내 해시값을 복사해서 제출하는 '재전송 공격'을 방지합니다.
	// 구분자(:)를 넣어 데이터가 섞여서 발생하는 해시 충돌을 방지합니다.
	data := fmt.Sprintf("%d:%d:%s:%d:%s:%d:%s", price, len(salt), salt, len(userID), userID, len(auctionID), auctionID)

	// hash.go의 HashString(SHA-256)을 사용하여 해시 생성
	return HashString(data)
}
