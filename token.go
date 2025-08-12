package authie

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
)

const SessionTokenLength = 40

func GenerateSecureToken() (string, error) {
	bytes := make([]byte, SessionTokenLength/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func getIPAddress(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		if ip := net.ParseIP(xff); ip != nil {
			return xff
		}
	}

	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return xri
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
