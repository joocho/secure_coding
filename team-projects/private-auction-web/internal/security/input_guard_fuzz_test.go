package security

import (
	"testing"
)

// FuzzSanitizeInput tests the input sanitization logic.
func FuzzSanitizeInput(f *testing.F) {
	f.Add("normal_input")
	f.Add("<script>alert(1)</script>")
	f.Add("admin'; DROP TABLE users; --")
	f.Add("user@example.com")

	f.Fuzz(func(t *testing.T, input string) {
		sanitized := SanitizeInput(input)

		// The result should only contain allowed characters: [a-zA-Z0-9@._-\s\p{Hangul}]
		for _, r := range sanitized {
			allowed := (r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') ||
				r == '@' || r == '.' || r == '_' || r == '-' ||
				r == ' ' || r == '\t' || r == '\n' || r == '\r' ||
				(r >= 0xAC00 && r <= 0xD7A3) // Hangul Syllables range

			if !allowed {
				t.Errorf("SanitizeInput returned forbidden character %q in %q", r, sanitized)
			}
		}
	})
}

// FuzzValidateInput tests the input validation logic.
func FuzzValidateInput(f *testing.F) {
	f.Add("validUser123", 4, 20)
	f.Add("short", 10, 20)
	f.Add("tooLongInputThatExceedsTheLimit", 4, 10)
	f.Add("invalid!char", 4, 20)

	f.Fuzz(func(t *testing.T, input string, minLen, maxLen int) {
		// Just ensure it doesn't panic
		_ = ValidateInput(input, minLen, maxLen)
	})
}

// FuzzContainsDangerousChars tests the dangerous character detection logic.
func FuzzContainsDangerousChars(f *testing.F) {
	f.Add("safe")
	f.Add("'; DROP TABLE users;")
	f.Add("<script>")

	f.Fuzz(func(t *testing.T, input string) {
		// Just ensure it doesn't panic
		_ = ContainsDangerousChars(input)
	})
}

// FuzzIsValidPrice tests the price validation logic.
func FuzzIsValidPrice(f *testing.F) {
	f.Add(1000)
	f.Add(-1)
	f.Add(2000000000)

	f.Fuzz(func(t *testing.T, price int) {
		// Just ensure it doesn't panic
		_ = IsValidPrice(price)
	})
}
