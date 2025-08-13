package utils

import (
	"strings"
	"testing"
)

func TestGenerateSecureToken(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"even length", 16},
		{"odd length", 17},
		{"small length", 4},
		{"large length", 64},
		{"zero length", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.length)
			if err != nil {
				t.Fatalf("GenerateSecureToken() error = %v", err)
			}

			if len(token) != tt.length {
				t.Errorf("GenerateSecureToken() length = %d, want %d", len(token), tt.length)
			}

			// Verify token contains only valid hex characters
			if tt.length > 0 {
				validHex := "0123456789abcdef"
				for _, char := range strings.ToLower(token) {
					if !strings.ContainsRune(validHex, char) {
						t.Errorf("GenerateSecureToken() contains invalid hex character: %c", char)
					}
				}
			}
		})
	}
}

func TestGenerateSecureTokenNegativeLength(t *testing.T) {
	_, err := GenerateSecureToken(-1)
	if err == nil {
		t.Error("GenerateSecureToken() with negative length should return an error")
	}
}

func TestGenerateSecureTokenUniqueness(t *testing.T) {
	const tokenLength = 32
	const numTokens = 1000

	tokens := make(map[string]bool)
	for i := 0; i < numTokens; i++ {
		token, err := GenerateSecureToken(tokenLength)
		if err != nil {
			t.Fatalf("GenerateSecureToken() error = %v", err)
		}

		if tokens[token] {
			t.Errorf("GenerateSecureToken() generated duplicate token: %s", token)
		}
		tokens[token] = true
	}
}

func TestGenerateSecureTokenRandomness(t *testing.T) {
	const tokenLength = 32
	const numTokens = 100

	tokens := make([]string, numTokens)
	for i := 0; i < numTokens; i++ {
		token, err := GenerateSecureToken(tokenLength)
		if err != nil {
			t.Fatalf("GenerateSecureToken() error = %v", err)
		}
		tokens[i] = token
	}

	// Check that tokens don't start with the same prefix (basic randomness check)
	prefixCounts := make(map[string]int)
	for _, token := range tokens {
		if len(token) >= 4 {
			prefix := token[:4]
			prefixCounts[prefix]++
		}
	}

	// In a truly random distribution, we shouldn't see many repeated prefixes
	for prefix, count := range prefixCounts {
		if count > numTokens/10 { // More than 10% of tokens have same prefix
			t.Errorf("Token prefix %s appears too frequently (%d times)", prefix, count)
		}
	}
}

func TestGenerateSecureTokenHexCharacters(t *testing.T) {
	token, err := GenerateSecureToken(20)
	if err != nil {
		t.Fatalf("GenerateSecureToken() error = %v", err)
	}

	validHex := "0123456789abcdef"
	for _, char := range strings.ToLower(token) {
		if !strings.ContainsRune(validHex, char) {
			t.Errorf("GenerateSecureToken() contains invalid hex character: %c", char)
		}
	}
}

func BenchmarkGenerateSecureToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSecureToken(32)
		if err != nil {
			b.Fatalf("GenerateSecureToken() error = %v", err)
		}
	}
}

func BenchmarkGenerateSecureTokenLarge(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSecureToken(128)
		if err != nil {
			b.Fatalf("GenerateSecureToken() error = %v", err)
		}
	}
}
