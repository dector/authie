package authie

import (
	"crypto/rand"
	"encoding/hex"
)

const SessionTokenLength = 40

func GenerateSecureToken() (string, error) {
	bytes := make([]byte, SessionTokenLength/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
