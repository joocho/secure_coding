package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	RSABits = 4096
)

// RSA Functions
func GenerateRSAKeyPair() (string, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, RSABits)
	if err != nil {
		return "", "", err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return string(privPEM), string(pubPEM), nil
}

func EncryptRSA(pubPEM string, plaintext []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to decode public key: not a valid PEM block")
	}
	// PEM 헤더 타입 검증 추가
	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("invalid key type: %s", block.Type)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plaintext, nil)
}

func DecryptRSA(privPEM string, ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to decode private key: not a valid PEM block")
	}
	// PEM 헤더 타입 검증 추가
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid key type: %s", block.Type)
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
}

// Envelope Encryption (AES-GCM)
func WrapKey(masterKey, data []byte) ([]byte, error) {
	defer ZeroingMemory(data) // 봉인 완료 후 원본 데이터(Key) 즉시 소거
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func UnwrapKey(masterKey, wrappedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(wrappedData) < nonceSize {
		return nil, errors.New("invalid wrapped data")
	}
	nonce, ciphertext := wrappedData[:nonceSize], wrappedData[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Ed25519 Functions
func GenerateEd25519KeyPair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return string(privPEM), string(pubPEM), nil
}

func SignMessage(privKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privKey, message)
}

func VerifySignature(pubKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}

func LoadEd25519PrivateKey(privPEM string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}
	return edPriv, nil
}

func LoadEd25519PublicKey(pubKey string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(pubKey)
	if trimmed == "" {
		return nil, errors.New("failed to decode public key")
	}

	// Backward compatibility: accept hex-encoded raw Ed25519 public key from DB.
	if raw, err := hex.DecodeString(trimmed); err == nil {
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(raw))
		}
		return ed25519.PublicKey(raw), nil
	}

	// Also support PEM-encoded PKIX public keys.
	block, _ := pem.Decode([]byte(trimmed))
	if block == nil {
		return nil, errors.New("failed to decode public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}
	return edPub, nil
}

// ExportEd25519PublicKeyToPEM은 Ed25519 공개키를 PEM 형식 문자열로 변환합니다.
func ExportEd25519PublicKeyToPEM(pub ed25519.PublicKey) string {
	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return string(pubPEM)
}

func GetServerPrivateKey() (ed25519.PrivateKey, error) {
	privPEM := os.Getenv("SERVER_PRIVATE_KEY")
	if privPEM == "" {
		// ⚠️ 주의: 실제 운영 환경에서는 절대 허용되지 않습니다.
		// 환경 변수가 없을 때 매번 새로운 키를 생성하면 영수증 검증이 불가능해집니다.
		// 테스트용 고정 키 시드 사용 (절대 프로덕션용 아님)
		seed := make([]byte, ed25519.SeedSize)
		copy(seed, "DEV-SERVER-SIGN-KEY-SEED-32-BYT") 
		return ed25519.NewKeyFromSeed(seed), nil
	}
	return LoadEd25519PrivateKey(privPEM)
}

func GetServerPublicKey() ed25519.PublicKey {
	priv, _ := GetServerPrivateKey()
	return priv.Public().(ed25519.PublicKey)
}

// VerifyReceipt는 서버의 공개키로 영수증 서명의 유효성을 검증합니다.
func VerifyReceipt(serverPubPEM string, bidID, auctionID, commitHash string, signature []byte) bool {
	pub, err := LoadEd25519PublicKey(serverPubPEM)
	if err != nil {
		return false
	}
	payload := fmt.Sprintf("RECEIPT:%s:%s:%s", bidID, auctionID, commitHash)
	return VerifySignature(pub, []byte(payload), signature)
}

// KEK Management with Rotation Support
var (
	// KEKs generated from environment secrets
	kekVersions = make(map[int][]byte)
	latestKEKVersion = 1
)

func init() {
	loadKEKs()
}

func loadKEKs() {
	env := os.Getenv("APP_ENV")
	isProd := env == "production"

	// Define version secrets from env vars
	secrets := map[int]string{
		1: os.Getenv("APP_MASTER_SECRET_V1"),
		2: os.Getenv("APP_MASTER_SECRET_V2"),
	}

	// Default dummy secrets for development
	devSecrets := map[int]string{
		1: "dev-only-insecure-master-secret-01",
		2: "dev-only-insecure-master-secret-02",
	}

	for ver, secret := range secrets {
		if secret == "" {
			if isProd {
				log.Fatalf("CRITICAL SECURITY ERROR: APP_MASTER_SECRET_V%d IS NOT SET IN PRODUCTION", ver)
			}
			secret = devSecrets[ver]
			if env != "test" {
				log.Printf("WARNING: Using dummy KEK V%d (NOT FOR PRODUCTION)", ver)
			}
		}

		// Derive actual 32-byte key using PBKDF2
		// In a real system, the salt should also be unique or stored securely
		salt := []byte("secure-auction-kek-salt-v" + fmt.Sprint(ver))
		derivedKey := pbkdf2.Key([]byte(secret), salt, 4096, 32, sha256.New)
		kekVersions[ver] = derivedKey
	}

	// Update latest version based on what's available
	for v := range kekVersions {
		if v > latestKEKVersion {
			latestKEKVersion = v
		}
	}
}

func GetKEK(version int) ([]byte, error) {
	kek, ok := kekVersions[version]
	if !ok {
		return nil, fmt.Errorf("KEK version %d not found", version)
	}
	return kek, nil
}

func GetLatestKEKVersion() int {
	return latestKEKVersion
}

func GetRootKEK() []byte {
	// 하위 호환성을 위해 최신 버전을 반환
	kek, _ := GetKEK(latestKEKVersion)
	return kek
}

// CalculatePublicKeyFingerprint는 공개키의 SHA-256 해시를 생성하여 
// 사용자가 자신의 키가 변조되지 않았는지 확인할 수 있는 고유 지문을 제공합니다.
func CalculatePublicKeyFingerprint(pubPEM string) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(pubPEM)))
	return hex.EncodeToString(h.Sum(nil))
}



// ZeroingMemory는 메모리의 민감한 바이트 슬라이스를 즉시 소거합니다.
func ZeroingMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
