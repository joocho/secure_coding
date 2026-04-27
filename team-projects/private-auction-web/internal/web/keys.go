package web

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"blind-auction-go/internal/db"
	"blind-auction-go/internal/security"
)

// ensureUserKey는 사용자의 Ed25519 개인키가 keys/ 디렉터리에 존재하는지 확인하고,
// 없으면 새로 생성한 뒤 공개키를 users 테이블에 저장합니다.
// (TUI의 checkOrSetupKey와 동일한 동작)
func ensureUserKey(userID, username string, userStore *db.UserStore) error {
	if err := os.MkdirAll("keys", 0700); err != nil {
		return fmt.Errorf("keys 디렉터리 생성 실패: %w", err)
	}

	keyFileName := filepath.Base(fmt.Sprintf("%s_ed25519.pem", username))

	root, err := os.OpenRoot("keys")
	if err != nil {
		return fmt.Errorf("keys 디렉터리 열기 실패: %w", err)
	}
	defer root.Close()

	_, statErr := root.Stat(keyFileName)
	fileExists := statErr == nil

	user, err := userStore.GetByID(userID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("사용자를 찾을 수 없습니다")
	}

	if fileExists && user.PublicKey != "" {
		return nil
	}

	privPEM, pubPEM, err := security.GenerateEd25519KeyPair()
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return errors.New("공개키 파싱 실패")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return errors.New("Ed25519 키가 아닙니다")
	}

	if err := userStore.UpdatePublicKey(userID, hex.EncodeToString([]byte(edPub))); err != nil {
		return err
	}
	if err := root.WriteFile(keyFileName, []byte(privPEM), 0600); err != nil {
		return err
	}
	return nil
}

// loadUserPrivateKey는 keys/<username>_ed25519.pem 을 읽어 Ed25519 개인키를 반환합니다.
func loadUserPrivateKey(username string) (ed25519.PrivateKey, error) {
	root, err := os.OpenRoot("keys")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	keyFileName := filepath.Base(fmt.Sprintf("%s_ed25519.pem", username))
	privPEMBytes, err := root.ReadFile(keyFileName)
	if err != nil {
		return nil, err
	}
	return security.LoadEd25519PrivateKey(string(privPEMBytes))
}
