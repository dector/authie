package authie

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Mock implementations for testing

type mockAuthActionHandler struct {
	unauthenticatedCalled bool
	authErrorCalled       bool
	lastError             error
	lastRequest           *http.Request
	lastWriter            http.ResponseWriter
}

func (m *mockAuthActionHandler) HandleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	m.unauthenticatedCalled = true
	m.lastWriter = w
	m.lastRequest = r
}

func (m *mockAuthActionHandler) HandleAuthError(w http.ResponseWriter, r *http.Request, err error) {
	m.authErrorCalled = true
	m.lastError = err
	m.lastWriter = w
	m.lastRequest = r
}

type mockSessionStore struct {
	sessions       map[string]*Session
	createError    error
	getError       error
	updateError    error
	revokeError    error
	updateCalled   bool
	getTokenCalled string
}

func (m *mockSessionStore) CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error) {
	if m.createError != nil {
		return nil, m.createError
	}
	session := &Session{
		ID:             1,
		UserID:         params.UserID,
		Token:          params.Token,
		ActiveUntil:    params.ActiveUntil,
		RenewableUntil: params.RenewableUntil,
		User:           &User{ID: params.UserID, Login: "testuser"},
	}
	m.sessions[params.Token] = session
	return session, nil
}

func (m *mockSessionStore) GetSessionByToken(ctx context.Context, params GetSessionByTokenParams) (*Session, error) {
	m.getTokenCalled = params.Token
	if m.getError != nil {
		return nil, m.getError
	}
	return m.sessions[params.Token], nil
}

func (m *mockSessionStore) UpdateSession(ctx context.Context, params UpdateSessionParams) error {
	m.updateCalled = true
	if m.updateError != nil {
		return m.updateError
	}
	// Move session from old token to new token
	for token, session := range m.sessions {
		if session.ID == params.SessionID {
			delete(m.sessions, token)
			updatedSession := &Session{
				ID:             session.ID,
				UserID:         session.UserID,
				Token:          params.Token,
				ActiveUntil:    params.ActiveUntil,
				RenewableUntil: params.RenewableUntil,
				Revoked:        session.Revoked,
				User:           session.User,
			}
			m.sessions[params.Token] = updatedSession
			break
		}
	}
	return nil
}

func (m *mockSessionStore) RevokeSession(ctx context.Context, params RevokeSessionParams) error {
	if m.revokeError != nil {
		return m.revokeError
	}
	for _, session := range m.sessions {
		if session.ID == params.SessionID {
			session.Revoked = true
			break
		}
	}
	return nil
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*Session),
	}
}

// Test DefaultAuthActionHandler

func TestDefaultAuthActionHandler_HandleUnauthenticated(t *testing.T) {
	// GIVEN: Setup a default auth action handler with login URL
	loginURL := "/login"
	handler := NewDefaultAuthActionHandler(loginURL)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)

	// WHEN: Handle an unauthenticated request
	handler.HandleUnauthenticated(w, r)

	// THEN: Should redirect to login URL with 303 status
	if w.Code != http.StatusSeeOther {
		t.Errorf("Expected status %d, got %d", http.StatusSeeOther, w.Code)
	}

	location := w.Header().Get("Location")
	if location != loginURL {
		t.Errorf("Expected redirect to %s, got %s", loginURL, location)
	}
}

func TestDefaultAuthActionHandler_HandleAuthError(t *testing.T) {
	// GIVEN: Setup a default auth action handler with login URL and an error
	loginURL := "/login"
	handler := NewDefaultAuthActionHandler(loginURL)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)
	err := errors.New("test error")

	// WHEN: Handle an authentication error
	handler.HandleAuthError(w, r, err)

	// THEN: Should redirect to login URL with 303 status
	if w.Code != http.StatusSeeOther {
		t.Errorf("Expected status %d, got %d", http.StatusSeeOther, w.Code)
	}

	location := w.Header().Get("Location")
	if location != loginURL {
		t.Errorf("Expected redirect to %s, got %s", loginURL, location)
	}
}

func TestDefaultAuthActionHandler_EmptyLoginURL(t *testing.T) {
	// GIVEN: Setup handler with empty login URL
	handler := NewDefaultAuthActionHandler("")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)

	// WHEN: Handle unauthenticated request with empty login URL
	handler.HandleUnauthenticated(w, r)

	// THEN: Should redirect to root path as http.Redirect converts empty URL to "/"
	if w.Code != http.StatusSeeOther {
		t.Errorf("Expected status %d, got %d", http.StatusSeeOther, w.Code)
	}

	location := w.Header().Get("Location")
	// http.Redirect converts empty URL to "/"
	if location != "/" {
		t.Errorf("Expected redirect location '/', got %s", location)
	}
}

// Test Middleware

func TestMiddleware_NoCookie(t *testing.T) {
	// GIVEN: Middleware setup with no authentication cookie in request
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	middleware := ac.Middleware(mockHandler)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	handler := middleware(nextHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)

	// WHEN: Process request without auth cookie
	handler.ServeHTTP(w, r)

	// THEN: Should call HandleUnauthenticated but not HandleAuthError
	if !mockHandler.unauthenticatedCalled {
		t.Error("HandleUnauthenticated should have been called")
	}
	if mockHandler.authErrorCalled {
		t.Error("HandleAuthError should not have been called")
	}
}

func TestMiddleware_InvalidCookieLength(t *testing.T) {
	// GIVEN: Middleware setup with auth cookie that has invalid length
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	middleware := ac.Middleware(mockHandler)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	handler := middleware(nextHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)
	// Add cookie with wrong length
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: "short"})

	// WHEN: Process request with invalid token length
	handler.ServeHTTP(w, r)

	// THEN: Should treat as unauthenticated, not as auth error
	if !mockHandler.unauthenticatedCalled {
		t.Error("HandleUnauthenticated should have been called")
	}
	if mockHandler.authErrorCalled {
		t.Error("HandleAuthError should not have been called")
	}
}

func TestMiddleware_VerifySessionError(t *testing.T) {
	// GIVEN: Middleware setup with session store that returns database error
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	store.getError = errors.New("database error")
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	middleware := ac.Middleware(mockHandler)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	handler := middleware(nextHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)
	// Add cookie with correct length
	validToken := "1234567890123456789012345678901234567890" // 40 chars
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: validToken})

	// WHEN: Process request when session verification fails with database error
	handler.ServeHTTP(w, r)

	// THEN: Should call HandleAuthError with the database error
	if mockHandler.unauthenticatedCalled {
		t.Error("HandleUnauthenticated should not have been called")
	}
	if !mockHandler.authErrorCalled {
		t.Error("HandleAuthError should have been called")
	}
	if mockHandler.lastError == nil || mockHandler.lastError.Error() != "database error" {
		t.Error("HandleAuthError should have been called with the correct error")
	}
}

func TestMiddleware_NilSession(t *testing.T) {
	// GIVEN: Middleware setup with valid token but no corresponding session in store
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	middleware := ac.Middleware(mockHandler)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	handler := middleware(nextHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)
	// Add cookie with correct length but no corresponding session
	validToken := "1234567890123456789012345678901234567890" // 40 chars
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: validToken})

	// WHEN: Process request with non-existent session
	handler.ServeHTTP(w, r)

	// THEN: Should treat as unauthenticated when session is nil
	if !mockHandler.unauthenticatedCalled {
		t.Error("HandleUnauthenticated should have been called")
	}
	if mockHandler.authErrorCalled {
		t.Error("HandleAuthError should not have been called")
	}
}

func TestMiddleware_ValidSessionNoRenewal(t *testing.T) {
	// GIVEN: Valid active session that doesn't need renewal
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	// Create a valid session
	validToken := "1234567890123456789012345678901234567890" // 40 chars
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          validToken,
		ActiveUntil:    now.Add(time.Hour),
		RenewableUntil: now.Add(24 * time.Hour),
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[validToken] = session

	middleware := ac.Middleware(mockHandler)

	nextCalled := false
	var contextUser *User
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		user := r.Context().Value("user")
		if user != nil {
			contextUser = user.(*User)
		}
	})

	handler := middleware(nextHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: validToken})

	// WHEN: Process request with valid, active session
	handler.ServeHTTP(w, r)

	// THEN: Should proceed to next handler with user in context, no renewal needed
	if mockHandler.unauthenticatedCalled {
		t.Error("HandleUnauthenticated should not have been called")
	}
	if mockHandler.authErrorCalled {
		t.Error("HandleAuthError should not have been called")
	}
	if !nextCalled {
		t.Error("Next handler should have been called")
	}
	if contextUser == nil {
		t.Error("User should be in context")
	}
	if contextUser.ID != 123 || contextUser.Login != "testuser" {
		t.Errorf("Expected user ID 123 and login 'testuser', got ID %d and login %s",
			contextUser.ID, contextUser.Login)
	}

	// Check that no new cookie was set (no renewal)
	cookies := w.Result().Cookies()
	if len(cookies) > 0 {
		t.Error("No new cookie should have been set")
	}
}

func TestMiddleware_ValidSessionWithRenewal(t *testing.T) {
	// GIVEN: Expired but renewable session that needs token renewal
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	// Create a session that needs renewal (expired but renewable)
	oldToken := "1234567890123456789012345678901234567890" // 40 chars
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          oldToken,
		ActiveUntil:    now.Add(-time.Hour), // Expired
		RenewableUntil: now.Add(time.Hour),  // But renewable
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[oldToken] = session

	middleware := ac.Middleware(mockHandler)

	nextCalled := false
	var contextUser *User
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		user := r.Context().Value("user")
		if user != nil {
			contextUser = user.(*User)
		}
	})

	handler := middleware(nextHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: oldToken})

	// WHEN: Process request with expired but renewable session
	handler.ServeHTTP(w, r)

	// THEN: Should renew session and proceed with new token cookie
	if mockHandler.unauthenticatedCalled {
		t.Error("HandleUnauthenticated should not have been called")
	}
	if mockHandler.authErrorCalled {
		t.Error("HandleAuthError should not have been called")
	}
	if !nextCalled {
		t.Error("Next handler should have been called")
	}
	if contextUser == nil {
		t.Error("User should be in context")
	}

	// Check that UpdateSession was called
	if !store.updateCalled {
		t.Error("UpdateSession should have been called for renewal")
	}

	// Check that new cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == "auth_session" {
			found = true
			// Just verify it's a different token and has correct length
			if cookie.Value == oldToken {
				t.Error("New cookie should have different token than old token")
			}
			if len(cookie.Value) != config.SessionTokenLength {
				t.Errorf("Expected cookie value length %d, got %d", config.SessionTokenLength, len(cookie.Value))
			}
		}
	}
	if !found {
		t.Error("New session cookie should have been set")
	}
}

func TestMiddleware_ExpiredNonRenewableSession(t *testing.T) {
	// GIVEN: Expired session that is also not renewable anymore
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	// Create a session that is expired and not renewable
	token := "1234567890123456789012345678901234567890" // 40 chars
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          token,
		ActiveUntil:    now.Add(-2 * time.Hour), // Expired
		RenewableUntil: now.Add(-time.Hour),     // Also not renewable
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[token] = session

	middleware := ac.Middleware(mockHandler)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	handler := middleware(nextHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: token})

	// WHEN: Process request with expired non-renewable session
	handler.ServeHTTP(w, r)

	// THEN: Should treat as unauthenticated
	if !mockHandler.unauthenticatedCalled {
		t.Error("HandleUnauthenticated should have been called")
	}
	if mockHandler.authErrorCalled {
		t.Error("HandleAuthError should not have been called")
	}
}

func TestMiddleware_ContextPropagation(t *testing.T) {
	// GIVEN: Valid session with user to test context propagation
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	// Create a valid session
	validToken := "1234567890123456789012345678901234567890" // 40 chars
	now := time.Now()
	testUser := &User{ID: 456, Login: "contextuser"}
	session := &Session{
		ID:             1,
		UserID:         456,
		Token:          validToken,
		ActiveUntil:    now.Add(time.Hour),
		RenewableUntil: now.Add(24 * time.Hour),
		User:           testUser,
	}
	store.sessions[validToken] = session

	middleware := ac.Middleware(mockHandler)

	var receivedContext context.Context
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContext = r.Context()
	})

	handler := middleware(nextHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: validToken})

	// WHEN: Process request to verify user context propagation
	handler.ServeHTTP(w, r)

	// THEN: Should propagate exact user instance in request context
	if receivedContext == nil {
		t.Fatal("Context should have been received")
	}

	user := receivedContext.Value("user")
	if user == nil {
		t.Error("User should be in context")
	}

	contextUser, ok := user.(*User)
	if !ok {
		t.Error("Context value should be a User pointer")
	}

	if contextUser != testUser {
		t.Error("Context should contain the exact same user instance")
	}
}

func TestMiddleware_MultipleRequests(t *testing.T) {
	// GIVEN: Two different valid sessions to test concurrent request handling
	config := NewConfig("auth_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	mockHandler := &mockAuthActionHandler{}

	// Create valid sessions for two different users
	token1 := "1111111111111111111111111111111111111111" // 40 chars
	token2 := "2222222222222222222222222222222222222222" // 40 chars
	now := time.Now()

	user1 := &User{ID: 1, Login: "user1"}
	user2 := &User{ID: 2, Login: "user2"}

	session1 := &Session{
		ID:             1,
		UserID:         1,
		Token:          token1,
		ActiveUntil:    now.Add(time.Hour),
		RenewableUntil: now.Add(24 * time.Hour),
		User:           user1,
	}
	session2 := &Session{
		ID:             2,
		UserID:         2,
		Token:          token2,
		ActiveUntil:    now.Add(time.Hour),
		RenewableUntil: now.Add(24 * time.Hour),
		User:           user2,
	}

	store.sessions[token1] = session1
	store.sessions[token2] = session2

	middleware := ac.Middleware(mockHandler)

	var receivedUsers []*User
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		receivedUsers = append(receivedUsers, user)
	})

	handler := middleware(nextHandler)

	// WHEN: Process multiple requests with different valid sessions
	// First request with token1
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/protected", nil)
	r1.AddCookie(&http.Cookie{Name: "auth_session", Value: token1})
	handler.ServeHTTP(w1, r1)

	// Second request with token2
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/protected", nil)
	r2.AddCookie(&http.Cookie{Name: "auth_session", Value: token2})
	handler.ServeHTTP(w2, r2)

	// THEN: Should handle each request with correct user context, no interference
	if len(receivedUsers) != 2 {
		t.Fatalf("Expected 2 users, got %d", len(receivedUsers))
	}

	if receivedUsers[0].ID != 1 || receivedUsers[0].Login != "user1" {
		t.Error("First request should have received user1")
	}

	if receivedUsers[1].ID != 2 || receivedUsers[1].Login != "user2" {
		t.Error("Second request should have received user2")
	}

	// Verify no interference between requests
	if mockHandler.unauthenticatedCalled || mockHandler.authErrorCalled {
		t.Error("No auth errors should have occurred for valid sessions")
	}
}
