package authie

import (
	"context"
	"net/http"
	"time"
)

type Config struct {
	CookieName       string
	ValidityTime     time.Duration
	RenewabilityTime time.Duration
	SameSite         http.SameSite
}

func NewConfig(cookieName string) Config {
	return Config{
		CookieName:       cookieName,
		ValidityTime:     3 * 24 * time.Hour, // 3 days
		RenewabilityTime: 7 * 24 * time.Hour, // 7 days
		SameSite:         http.SameSiteLaxMode,
	}
}

type User struct {
	ID    int
	Login string
}

type Session struct {
	ID             int
	UserID         int
	Token          string
	ActiveUntil    time.Time
	RenewableUntil time.Time
	IPAddress      string
	Revoked        bool
	User           *User
}

// SessionStore method parameters
type CreateSessionParams struct {
	UserID         int
	Token          string
	ActiveUntil    time.Time
	RenewableUntil time.Time
	IPAddress      string
}

type GetSessionByTokenParams struct {
	Token string
}

type UpdateSessionParams struct {
	SessionID      int
	Token          string
	ActiveUntil    time.Time
	RenewableUntil time.Time
}

type RevokeSessionParams struct {
	SessionID int
}

type SessionStore interface {
	CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error)
	GetSessionByToken(ctx context.Context, params GetSessionByTokenParams) (*Session, error)
	UpdateSession(ctx context.Context, params UpdateSessionParams) error
	RevokeSession(ctx context.Context, params RevokeSessionParams) error
}

type AuthController struct {
	config Config
	store  SessionStore
}

func NewAuthController(config Config, store SessionStore) *AuthController {
	return &AuthController{
		config: config,
		store:  store,
	}
}

func (ac *AuthController) CreateSession(ctx context.Context, userID int, r *http.Request) (*Session, error) {
	token, err := GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	activeUntil := now.Add(ac.config.ValidityTime)
	renewableUntil := now.Add(ac.config.RenewabilityTime)

	ipAddress := getIPAddress(r)

	params := CreateSessionParams{
		UserID:         userID,
		Token:          token,
		ActiveUntil:    activeUntil,
		RenewableUntil: renewableUntil,
		IPAddress:      ipAddress,
	}

	return ac.store.CreateSession(ctx, params)
}

func (ac *AuthController) VerifySession(ctx context.Context, token string) (*Session, bool, error) {
	params := GetSessionByTokenParams{Token: token}
	session, err := ac.store.GetSessionByToken(ctx, params)
	if err != nil {
		return nil, false, err
	}

	if session.Revoked {
		return nil, false, nil
	}

	now := time.Now()

	if now.After(session.ActiveUntil) {
		if now.After(session.RenewableUntil) {
			return nil, false, nil
		}

		newToken, err := GenerateSecureToken()
		if err != nil {
			return nil, false, err
		}

		newActiveUntil := now.Add(ac.config.ValidityTime)
		newRenewableUntil := now.Add(ac.config.RenewabilityTime)

		updateParams := UpdateSessionParams{
			SessionID:      session.ID,
			Token:          newToken,
			ActiveUntil:    newActiveUntil,
			RenewableUntil: newRenewableUntil,
		}
		err = ac.store.UpdateSession(ctx, updateParams)
		if err != nil {
			return nil, false, err
		}

		getParams := GetSessionByTokenParams{Token: newToken}
		renewedSession, err := ac.store.GetSessionByToken(ctx, getParams)
		if err != nil {
			return nil, false, err
		}

		return renewedSession, true, nil
	}

	return session, false, nil
}

func (ac *AuthController) CloseSession(ctx context.Context, sessionID int) error {
	params := RevokeSessionParams{SessionID: sessionID}
	return ac.store.RevokeSession(ctx, params)
}

func (ac *AuthController) SetSessionCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     ac.config.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: ac.config.SameSite,
		MaxAge:   int(ac.config.RenewabilityTime.Seconds()),
	}
	http.SetCookie(w, cookie)
}

func (ac *AuthController) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     ac.config.CookieName,
		Value:    "-",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: ac.config.SameSite,
		MaxAge:   1,
	}
	http.SetCookie(w, cookie)
}

func (ac *AuthController) GetSessionFromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie(ac.config.CookieName)
	if err != nil || len(cookie.Value) != SessionTokenLength {
		return nil, false
	}

	session, _, err := ac.VerifySession(r.Context(), cookie.Value)
	if err != nil || session == nil {
		return nil, false
	}

	return session, true
}
