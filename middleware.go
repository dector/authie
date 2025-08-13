package authie

import (
	"context"
	"net/http"
)

// AuthActionHandler defines what actions to take for auth-related events
type AuthActionHandler interface {
	// HandleUnauthenticated is called when no valid session is found
	HandleUnauthenticated(w http.ResponseWriter, r *http.Request)
	// HandleAuthError is called when there's an error during authentication
	HandleAuthError(w http.ResponseWriter, r *http.Request, err error)
}

// DefaultAuthActionHandler provides default redirect-based auth actions
type DefaultAuthActionHandler struct {
	LoginURL string
}

// NewDefaultAuthActionHandler creates a default handler that redirects to login
func NewDefaultAuthActionHandler(loginURL string) *DefaultAuthActionHandler {
	return &DefaultAuthActionHandler{
		LoginURL: loginURL,
	}
}

func (h *DefaultAuthActionHandler) HandleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, h.LoginURL, http.StatusSeeOther)
}

func (h *DefaultAuthActionHandler) HandleAuthError(w http.ResponseWriter, r *http.Request, err error) {
	http.Redirect(w, r, h.LoginURL, http.StatusSeeOther)
}

func (ac *AuthController) Middleware(actionHandler AuthActionHandler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			cookie, err := r.Cookie(ac.config.CookieName)
			if err != nil || len(cookie.Value) != ac.config.SessionTokenLength {
				actionHandler.HandleUnauthenticated(w, r)
				return
			}

			session, renewed, err := ac.VerifySession(ctx, cookie.Value)
			if err != nil {
				actionHandler.HandleAuthError(w, r, err)
				return
			}

			if session == nil {
				actionHandler.HandleUnauthenticated(w, r)
				return
			}

			if renewed {
				ac.SetSessionCookie(w, session.Token)
			}

			ctx = context.WithValue(ctx, "user", session.User)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
