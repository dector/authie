package internal

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateSecureToken(length int) (string, error) {
	// For odd lengths, generate one extra byte and trim the result
	byteLength := length / 2
	if length%2 != 0 {
		byteLength++
	}

	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	token := hex.EncodeToString(bytes)

	// Trim to exact length if we generated extra
	if len(token) > length {
		token = token[:length]
	}

	return token, nil
}
