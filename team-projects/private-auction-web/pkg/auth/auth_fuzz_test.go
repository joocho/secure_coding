package auth

import (
	"testing"
)

// FuzzValidatePassword tests the password strength validation logic.
func FuzzValidatePassword(f *testing.F) {
	f.Add("Password123!")
	f.Add("short")
	f.Add("nonumbers")
	f.Add("NOUPPER123!")
	f.Add("nolower123!")
	f.Add("nospecial123")

	f.Fuzz(func(t *testing.T, password string) {
		// Just ensure it doesn't panic
		_ = ValidatePassword(password)
	})
}
