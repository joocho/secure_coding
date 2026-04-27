package security

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateSaltBytes 지정된 크기의 랜덤 바이트 슬라이스(솔트)를 생성합니다.
func GenerateSaltBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateDefaultSaltBytes 설정 파일(config.go)의 Argon2SaltLength를 사용하여 솔트를 생성합니다.
func GenerateDefaultSaltBytes() ([]byte, error) {
	return GenerateSaltBytes(Argon2SaltLength)
}

// GenerateSalt 지정된 크기의 랜덤 솔트를 생성하고 16진수 문자열로 반환합니다.
func GenerateSalt(size int) (string, error) {
	b, err := GenerateSaltBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateDefaultSalt 설정 파일(config.go)의 Argon2SaltLength를 사용하여 16진수 솔트 문자열을 생성합니다.
func GenerateDefaultSalt() (string, error) {
	return GenerateSalt(Argon2SaltLength)
}
