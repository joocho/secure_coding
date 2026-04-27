package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"blind-auction-go/internal/security"
	"blind-auction-go/pkg/models"
)

func (s *Server) handleBidSubmit(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.requireRole(w, r, u, models.RoleBidder) {
		return
	}
	auctionID := r.PathValue("id")

	priceStr := strings.TrimSpace(r.FormValue("price"))
	price, err := strconv.Atoi(priceStr)
	if err != nil || price <= 0 {
		s.setFlash(w, "err", "입찰가는 1 이상의 정수여야 합니다")
		http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
		return
	}

	auc, err := s.AuctionService.GetAuction(auctionID)
	if err != nil {
		s.setFlash(w, "err", "경매를 찾을 수 없습니다")
		http.Redirect(w, r, "/auctions", http.StatusSeeOther)
		return
	}

	// 1. DEK + nonce 생성
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		s.setFlash(w, "err", "DEK 생성 실패")
		http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
		return
	}
	nonceBytes := make([]byte, 12)
	if _, err := rand.Read(nonceBytes); err != nil {
		s.setFlash(w, "err", "nonce 생성 실패")
		http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
		return
	}
	nonceStr := base64.StdEncoding.EncodeToString(nonceBytes)

	// 2. AES-GCM으로 입찰가 암호화
	priceData := []byte(strconv.Itoa(price))
	block, err := aes.NewCipher(dek)
	if err != nil {
		s.setFlash(w, "err", "암호화 실패")
		http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		s.setFlash(w, "err", "GCM 초기화 실패")
		http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
		return
	}
	ciphertextBid := gcm.Seal(nil, nonceBytes, priceData, nil)

	// 3. RSA-OAEP로 DEK 봉인
	encryptedDEK, err := security.EncryptRSA(auc.PublicKey, dek)
	if err != nil {
		s.setFlash(w, "err", "RSA 봉인 실패")
		http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
		return
	}
	defer security.ZeroingMemory(dek)

	// 4. 커밋 해시
	commitHash := security.GenerateCommitment(price, nonceStr, u.UserID)

	// 5. Ed25519 서명
	privKey, err := loadUserPrivateKey(u.Username)
	if err != nil {
		s.setFlash(w, "err", "개인키를 찾을 수 없습니다. 다시 로그인해 주세요.")
		http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
		return
	}
	defer security.ZeroingMemory(privKey)

	signedPayload := fmt.Sprintf("%s:%x:%x:%s", auc.ID, encryptedDEK, ciphertextBid, commitHash)
	signature := security.SignMessage(privKey, []byte(signedPayload))

	// 6. 제출
	receipt, err := s.BidService.SubmitBid(u.UserID, auc.ID, encryptedDEK, ciphertextBid, nonceStr, commitHash, signature)
	if err != nil {
		s.setFlash(w, "err", err.Error())
		http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
		return
	}

	s.setFlash(w, "ok", fmt.Sprintf("입찰이 제출되었습니다. 영수증: %s", receipt.BidID))
	http.Redirect(w, r, "/auctions/"+auctionID, http.StatusSeeOther)
}
