package security

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

//dvwa 참조

// SanitizeInput은 입력값을 정형화(Canonicalization)하고 허용된 문자 이외의 위험 요소를 제거합니다.
func SanitizeInput(input string) string {
	// 1. 공백 제거 및 UTF-8 정규화 (기본적인 Trim)
	input = strings.TrimSpace(input)

	// 2. 제어 문자 및 널 바이트, ESC(\x1b), DEL(0x7f) 제거 (G304/CWE-22/CWE-116 대응)
	// 0x00-0x1F (공백 제외), 0x7F 및 ESC(0x1B) 문자를 제거합니다.
	input = strings.Map(func(r rune) rune {
		// ASCII 제어 문자 (0x00-0x1F), DEL (0x7F) 필터링
		// \t, \n, \r은 필요에 따라 허용할 수 있으나 보안상 엄격하게 관리
		if (r < 32 && r != '\t' && r != '\n' && r != '\r') || r == 127 {
			return -1
		}
		return r
	}, input)

	// 3. ANSI Escape Sequences (\x1b[...]m 등) 제거
	// 터미널 인젝션 방지를 위해 ESC 문자(\x1b)로 시작하는 제어 시퀀스를 정규식으로 제거
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	input = ansiRegex.ReplaceAllString(input, "")
	input = strings.ReplaceAll(input, "\x1b", "") // 잔여 ESC 문자 제거

	// 4. 화이트리스트 필터링: 영문, 숫자, 한글, 공백, 일부 특수문자(@._-) 허용
	// 경매 제목 등을 고려하여 한글(\p{Hangul})과 공백을 명시적으로 허용하는 패턴 사용
	reg := regexp.MustCompile(`[^\p{Hangul}a-zA-Z0-9@._\-\s]`)
	result := reg.ReplaceAllString(input, "")
	return result
}

// ContainsDangerousChars는 입력값에 SQL 인젝션, 쉘 명령어, 경로 조작 등에 사용되는 위험 패턴이 있는지 확인합니다.
func ContainsDangerousChars(input string) bool {
	// ANSI Escape Sequence 감지
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	if ansiRegex.MatchString(input) {
		return true
	}

	// OWASP 권고 위험 패턴: 널 바이트, 개행, 상대 경로, 인젝션 특수문자
	dangerousPatterns := []string{
		"\x00", "\x1b", "\x7f", // 널 바이트, ESC, DEL
		"\r", "\n",             // 개행
		"../", "..\\",          // 경로 조작 (Directory Traversal)
		"'", "\"", ";", "--", "/*", "*/", // SQL 인젝션
		"`", "$", "|", "&", ">", "<",     // Shell 및 HTML 인젝션
		"(", ")", "{", "}", "\\",         // 기타 위험 기호
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}

// ValidateInput은 입력값의 길이와 구조적 유효성을 엄격하게 체크합니다. (Strict Whitelist)
func ValidateInput(input string, minLen, maxLen int) bool {
	length := utf8.RuneCountInString(input)
	if length < minLen || length > maxLen {
		return false
	}

	// 보안이 중요한 필드(ID, Hash 등)는 공백 없이 영문/숫자만 허용
	match, _ := regexp.MatchString(`^[a-zA-Z0-9@._-]+$`, input)
	return match
}

// IsValidPrice는 입찰가가 유효한 범위(0~10억)인지 확인합니다.
func IsValidPrice(price int) bool {
	return price > 0 && price < 1000000000
}

// ValidateHash는 SHA-256 해시값의 형식을 검증합니다. (64자리 16진수)
func ValidateHash(hash string) bool {
	matched, _ := regexp.MatchString(`^[0-9a-f]{64}$`, strings.ToLower(hash))
	return matched
}

// IsStrongPassword는 가이드라인(8~16자, 대소문자/숫자/특수문자 조합)에 따른 강력한 비밀번호 여부를 확인합니다.
func IsStrongPassword(password string) error {
	length := utf8.RuneCountInString(password)
	if length < 8 || length > 16 {
		return fmt.Errorf("비밀번호는 8~16자 사이여야 합니다")
	}

	patterns := []struct {
		regex *regexp.Regexp
		msg   string
	}{
		{regexp.MustCompile(`[A-Z]`), "대문자"},
		{regexp.MustCompile(`[a-z]`), "소문자"},
		{regexp.MustCompile(`[0-9]`), "숫자"},
		{regexp.MustCompile(`[!@#$%^&*()-_=+\[\]{}|;:,.<>/?]`), "특수문자"},
	}

	for _, p := range patterns {
		if !p.regex.MatchString(password) {
			return fmt.Errorf("비밀번호에는 최소 하나의 %s가 포함되어야 합니다", p.msg)
		}
	}

	return nil
}

// SanitizeTUI는 TUI(Terminal UI) 출력 시 터미널 인젝션 및 깨짐을 방지하기 위해
// 유효하지 않은 UTF-8 문자나 위험한 제어 문자를 필터링합니다.
func SanitizeTUI(input string) string {
	// 1. 유효하지 않은 UTF-8 시퀀스 제거
	if !utf8.ValidString(input) {
		v := make([]rune, 0, len(input))
		for i, r := range input {
			if r == utf8.RuneError {
				_, size := utf8.DecodeRuneInString(input[i:])
				if size == 1 {
					continue // 유효하지 않은 바이트 건너뜀
				}
			}
			v = append(v, r)
		}
		input = string(v)
	}

	// 2. 제어 문자 필터링 (개행, 탭 등 레이아웃 필수 문자 제외)
	// 0x00-0x1F 범위에서 \n(10), \r(13), \t(9)를 제외한 문자 및 0x7F(DEL) 제거
	input = strings.Map(func(r rune) rune {
		if (r < 32 && r != '\t' && r != '\n' && r != '\r') || r == 127 {
			return -1
		}
		return r
	}, input)

	return input
}
