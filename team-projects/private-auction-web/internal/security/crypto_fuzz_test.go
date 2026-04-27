package security

import (
	"bytes"
	"testing"
)

// FuzzWrapUnwrapKey tests the AES-GCM envelope encryption logic.
func FuzzWrapUnwrapKey(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("master-key-32-bytes-long-1234567"), []byte("sensitive-data-to-wrap"))
	f.Add([]byte("short-key"), []byte("data"))

	f.Fuzz(func(t *testing.T, masterKey []byte, data []byte) {
		// AES requires keys of 16, 24, or 32 bytes.
		// Our implementation uses aes.NewCipher which will error if the key is invalid.
		wrapped, err := WrapKey(masterKey, data)
		if err != nil {
			// If it fails, it should be due to invalid key size.
			if len(masterKey) != 16 && len(masterKey) != 24 && len(masterKey) != 32 {
				return
			}
			t.Fatalf("WrapKey failed with valid key size %d: %v", len(masterKey), err)
		}

		unwrapped, err := UnwrapKey(masterKey, wrapped)
		if err != nil {
			t.Fatalf("UnwrapKey failed: %v", err)
		}

		if !bytes.Equal(data, unwrapped) {
			t.Errorf("Unwrapped data does not match original: got %x, want %x", unwrapped, data)
		}
	})
}

// FuzzRSAEncryptDecrypt tests the RSA encryption and decryption logic.
func FuzzRSAEncryptDecrypt(f *testing.F) {
	privPEM, pubPEM, err := GenerateRSAKeyPair()
	if err != nil {
		f.Fatalf("failed to generate RSA key pair: %v", err)
	}

	f.Add([]byte("hello world"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		// RSA OAEP with SHA-256 has a maximum message length:
		// maxLen = KeySize - 2*HashSize - 2
		// For 4096-bit RSA and SHA-256 (32 bytes): 512 - 64 - 2 = 446 bytes
		if len(data) > 446 {
			return
		}

		encrypted, err := EncryptRSA(pubPEM, data)
		if err != nil {
			t.Fatalf("EncryptRSA failed: %v", err)
		}

		decrypted, err := DecryptRSA(privPEM, encrypted)
		if err != nil {
			t.Fatalf("DecryptRSA failed: %v", err)
		}

		if !bytes.Equal(data, decrypted) {
			t.Errorf("Decrypted data does not match original: got %x, want %x", decrypted, data)
		}
	})
}

// FuzzEd25519SignVerify tests the Ed25519 signing and verification logic.
func FuzzEd25519SignVerify(f *testing.F) {
	privPEM, pubPEM, err := GenerateEd25519KeyPair()
	if err != nil {
		f.Fatalf("failed to generate Ed25519 key pair: %v", err)
	}

	priv, err := LoadEd25519PrivateKey(privPEM)
	if err != nil {
		f.Fatalf("failed to load private key: %v", err)
	}

	pub, err := LoadEd25519PublicKey(pubPEM)
	if err != nil {
		f.Fatalf("failed to load public key: %v", err)
	}

	f.Add([]byte("message to sign"))

	f.Fuzz(func(t *testing.T, message []byte) {
		signature := SignMessage(priv, message)
		
		if !VerifySignature(pub, message, signature) {
			t.Errorf("Signature verification failed for message: %x", message)
		}

		// Tamper with message
		if len(message) > 0 {
			message[0] ^= 0xFF
			if VerifySignature(pub, message, signature) {
				t.Errorf("Signature verification should have failed for tampered message")
			}
		}
	})
}
