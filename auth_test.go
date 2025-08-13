package authie

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test Config struct and NewConfig function

func TestNewConfig(t *testing.T) {
	// GIVEN: A cookie name for configuration
	cookieName := "test_session"

	// WHEN: Creating a new config
	config := NewConfig(cookieName)

	// THEN: Should have proper defaults set
	if config.CookieName != cookieName {
		t.Errorf("Expected CookieName %s, got %s", cookieName, config.CookieName)
	}
	if config.SessionTokenLength != DefaultSessionTokenLength {
		t.Errorf("Expected SessionTokenLength %d, got %d", DefaultSessionTokenLength, config.SessionTokenLength)
	}
	if config.ValidityTime != 3*24*time.Hour {
		t.Errorf("Expected ValidityTime %v, got %v", 3*24*time.Hour, config.ValidityTime)
	}
	if config.RenewabilityTime != 7*24*time.Hour {
		t.Errorf("Expected RenewabilityTime %v, got %v", 7*24*time.Hour, config.RenewabilityTime)
	}
	if config.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSite %v, got %v", http.SameSiteLaxMode, config.SameSite)
	}
}

func TestConfig_CustomValues(t *testing.T) {
	// GIVEN: A config with custom values
	config := Config{
		CookieName:         "custom_cookie",
		SessionTokenLength: 64,
		ValidityTime:       time.Hour,
		RenewabilityTime:   2 * time.Hour,
		SameSite:           http.SameSiteStrictMode,
	}

	// WHEN/THEN: Values should be preserved as set
	if config.CookieName != "custom_cookie" {
		t.Errorf("Expected CookieName custom_cookie, got %s", config.CookieName)
	}
	if config.SessionTokenLength != 64 {
		t.Errorf("Expected SessionTokenLength 64, got %d", config.SessionTokenLength)
	}
	if config.ValidityTime != time.Hour {
		t.Errorf("Expected ValidityTime %v, got %v", time.Hour, config.ValidityTime)
	}
	if config.RenewabilityTime != 2*time.Hour {
		t.Errorf("Expected RenewabilityTime %v, got %v", 2*time.Hour, config.RenewabilityTime)
	}
	if config.SameSite != http.SameSiteStrictMode {
		t.Errorf("Expected SameSite %v, got %v", http.SameSiteStrictMode, config.SameSite)
	}
}

// Test AuthController constructor

func TestNewAuthController(t *testing.T) {
	// GIVEN: A valid config and mock store
	config := NewConfig("test_session")
	store := newMockSessionStore()

	// WHEN: Creating a new auth controller
	ac := NewAuthController(config, store)

	// THEN: Should return properly initialized controller
	if ac == nil {
		t.Fatal("NewAuthController should not return nil")
	}
	if ac.config.CookieName != config.CookieName {
		t.Errorf("Expected config.CookieName %s, got %s", config.CookieName, ac.config.CookieName)
	}
	if ac.store != store {
		t.Error("Expected store to be set correctly")
	}
}

// Test CreateSession method

func TestAuthController_CreateSession(t *testing.T) {
	// GIVEN: Auth controller with mock store
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()
	userID := 123

	r := httptest.NewRequest("GET", "/", nil)

	// WHEN: Creating a session
	session, err := ac.CreateSession(ctx, userID, r)

	// THEN: Should create session successfully
	if err != nil {
		t.Fatalf("CreateSession should not return error: %v", err)
	}
	if session == nil {
		t.Fatal("CreateSession should return a session")
	}
	if session.UserID != userID {
		t.Errorf("Expected UserID %d, got %d", userID, session.UserID)
	}
	if len(session.Token) != config.SessionTokenLength {
		t.Errorf("Expected token length %d, got %d", config.SessionTokenLength, len(session.Token))
	}

	// Check time calculations
	now := time.Now()
	expectedActiveUntil := now.Add(config.ValidityTime)
	expectedRenewableUntil := now.Add(config.RenewabilityTime)

	// Allow some tolerance for time differences (1 second)
	tolerance := time.Second
	if session.ActiveUntil.Sub(expectedActiveUntil).Abs() > tolerance {
		t.Errorf("ActiveUntil time calculation incorrect")
	}
	if session.RenewableUntil.Sub(expectedRenewableUntil).Abs() > tolerance {
		t.Errorf("RenewableUntil time calculation incorrect")
	}
}

func TestAuthController_CreateSession_StoreError(t *testing.T) {
	// GIVEN: Auth controller with failing store
	config := NewConfig("test_session")
	store := newMockSessionStore()
	store.createError = errors.New("database error")
	ac := NewAuthController(config, store)
	ctx := context.Background()

	r := httptest.NewRequest("GET", "/", nil)

	// WHEN: Creating a session with store error
	session, err := ac.CreateSession(ctx, 123, r)

	// THEN: Should return the store error
	if err == nil {
		t.Error("CreateSession should return error when store fails")
	}
	if err.Error() != "database error" {
		t.Errorf("Expected error 'database error', got %v", err)
	}
	if session != nil {
		t.Error("CreateSession should return nil session on error")
	}
}

// Test VerifySession method

func TestAuthController_VerifySession_ValidActiveSession(t *testing.T) {
	// GIVEN: Auth controller with valid active session
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	token := "1234567890123456789012345678901234567890"
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          token,
		ActiveUntil:    now.Add(time.Hour),
		RenewableUntil: now.Add(24 * time.Hour),
		Revoked:        false,
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[token] = session

	// WHEN: Verifying the session
	returnedSession, renewed, err := ac.VerifySession(ctx, token)

	// THEN: Should return session without renewal
	if err != nil {
		t.Fatalf("VerifySession should not return error: %v", err)
	}
	if returnedSession == nil {
		t.Fatal("VerifySession should return session")
	}
	if renewed {
		t.Error("Session should not be renewed when still active")
	}
	if returnedSession.Token != token {
		t.Errorf("Expected token %s, got %s", token, returnedSession.Token)
	}
	if store.updateCalled {
		t.Error("UpdateSession should not be called for active session")
	}
}

func TestAuthController_VerifySession_ExpiredRenewableSession(t *testing.T) {
	// GIVEN: Auth controller with expired but renewable session
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	oldToken := "1234567890123456789012345678901234567890"
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          oldToken,
		ActiveUntil:    now.Add(-time.Hour), // Expired
		RenewableUntil: now.Add(time.Hour),  // But renewable
		Revoked:        false,
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[oldToken] = session

	// WHEN: Verifying the expired session
	returnedSession, renewed, err := ac.VerifySession(ctx, oldToken)

	// THEN: Should renew and return new session
	if err != nil {
		t.Fatalf("VerifySession should not return error: %v", err)
	}
	if returnedSession == nil {
		t.Fatal("VerifySession should return renewed session")
	}
	if !renewed {
		t.Error("Session should be marked as renewed")
	}
	if returnedSession.Token == oldToken {
		t.Error("Renewed session should have different token")
	}
	if len(returnedSession.Token) != config.SessionTokenLength {
		t.Errorf("Expected token length %d, got %d", config.SessionTokenLength, len(returnedSession.Token))
	}
	if !store.updateCalled {
		t.Error("UpdateSession should be called for session renewal")
	}
}

func TestAuthController_VerifySession_ExpiredNonRenewableSession(t *testing.T) {
	// GIVEN: Auth controller with expired and non-renewable session
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	token := "1234567890123456789012345678901234567890"
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          token,
		ActiveUntil:    now.Add(-2 * time.Hour), // Expired
		RenewableUntil: now.Add(-time.Hour),     // Also not renewable
		Revoked:        false,
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[token] = session

	// WHEN: Verifying the expired non-renewable session
	returnedSession, renewed, err := ac.VerifySession(ctx, token)

	// THEN: Should return nil session
	if err != nil {
		t.Fatalf("VerifySession should not return error: %v", err)
	}
	if returnedSession != nil {
		t.Error("VerifySession should return nil for expired non-renewable session")
	}
	if renewed {
		t.Error("Session should not be marked as renewed")
	}
}

func TestAuthController_VerifySession_RevokedSession(t *testing.T) {
	// GIVEN: Auth controller with revoked session
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	token := "1234567890123456789012345678901234567890"
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          token,
		ActiveUntil:    now.Add(time.Hour),
		RenewableUntil: now.Add(24 * time.Hour),
		Revoked:        true, // Revoked
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[token] = session

	// WHEN: Verifying the revoked session
	returnedSession, renewed, err := ac.VerifySession(ctx, token)

	// THEN: Should return nil session
	if err != nil {
		t.Fatalf("VerifySession should not return error: %v", err)
	}
	if returnedSession != nil {
		t.Error("VerifySession should return nil for revoked session")
	}
	if renewed {
		t.Error("Revoked session should not be renewed")
	}
}

func TestAuthController_VerifySession_NonExistentSession(t *testing.T) {
	// GIVEN: Auth controller with empty store
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	token := "1234567890123456789012345678901234567890"

	// WHEN: Verifying non-existent session
	returnedSession, renewed, err := ac.VerifySession(ctx, token)

	// THEN: Should return nil session
	if err != nil {
		t.Fatalf("VerifySession should not return error: %v", err)
	}
	if returnedSession != nil {
		t.Error("VerifySession should return nil for non-existent session")
	}
	if renewed {
		t.Error("Non-existent session should not be marked as renewed")
	}
}

func TestAuthController_VerifySession_StoreGetError(t *testing.T) {
	// GIVEN: Auth controller with failing store
	config := NewConfig("test_session")
	store := newMockSessionStore()
	store.getError = errors.New("database error")
	ac := NewAuthController(config, store)
	ctx := context.Background()

	token := "1234567890123456789012345678901234567890"

	// WHEN: Verifying session with store error
	returnedSession, renewed, err := ac.VerifySession(ctx, token)

	// THEN: Should return the store error
	if err == nil {
		t.Error("VerifySession should return error when store fails")
	}
	if err.Error() != "database error" {
		t.Errorf("Expected error 'database error', got %v", err)
	}
	if returnedSession != nil {
		t.Error("VerifySession should return nil session on error")
	}
	if renewed {
		t.Error("Session should not be marked as renewed on error")
	}
}

func TestAuthController_VerifySession_StoreUpdateError(t *testing.T) {
	// GIVEN: Auth controller with expired session and failing update
	config := NewConfig("test_session")
	store := newMockSessionStore()
	store.updateError = errors.New("update failed")
	ac := NewAuthController(config, store)
	ctx := context.Background()

	oldToken := "1234567890123456789012345678901234567890"
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          oldToken,
		ActiveUntil:    now.Add(-time.Hour), // Expired
		RenewableUntil: now.Add(time.Hour),  // But renewable
		Revoked:        false,
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[oldToken] = session

	// WHEN: Verifying expired session with update error
	returnedSession, renewed, err := ac.VerifySession(ctx, oldToken)

	// THEN: Should return update error
	if err == nil {
		t.Error("VerifySession should return error when update fails")
	}
	if err.Error() != "update failed" {
		t.Errorf("Expected error 'update failed', got %v", err)
	}
	if returnedSession != nil {
		t.Error("VerifySession should return nil session on update error")
	}
	if renewed {
		t.Error("Session should not be marked as renewed on update error")
	}
}

// Test CloseSession method

func TestAuthController_CloseSession(t *testing.T) {
	// GIVEN: Auth controller with valid session
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	sessionID := 123

	// WHEN: Closing the session
	err := ac.CloseSession(ctx, sessionID)

	// THEN: Should revoke session successfully
	if err != nil {
		t.Fatalf("CloseSession should not return error: %v", err)
	}
}

func TestAuthController_CloseSession_StoreError(t *testing.T) {
	// GIVEN: Auth controller with failing store
	config := NewConfig("test_session")
	store := newMockSessionStore()
	store.revokeError = errors.New("revoke failed")
	ac := NewAuthController(config, store)
	ctx := context.Background()

	sessionID := 123

	// WHEN: Closing session with store error
	err := ac.CloseSession(ctx, sessionID)

	// THEN: Should return the store error
	if err == nil {
		t.Error("CloseSession should return error when store fails")
	}
	if err.Error() != "revoke failed" {
		t.Errorf("Expected error 'revoke failed', got %v", err)
	}
}

// Test cookie management methods

func TestAuthController_SetSessionCookie(t *testing.T) {
	// GIVEN: Auth controller with custom config
	config := Config{
		CookieName:         "custom_session",
		SessionTokenLength: 32,
		ValidityTime:       time.Hour,
		RenewabilityTime:   24 * time.Hour,
		SameSite:           http.SameSiteStrictMode,
	}
	store := newMockSessionStore()
	ac := NewAuthController(config, store)

	token := "test_token_12345678901234567890"
	w := httptest.NewRecorder()

	// WHEN: Setting session cookie
	ac.SetSessionCookie(w, token)

	// THEN: Should set cookie with correct attributes
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "custom_session" {
		t.Errorf("Expected cookie name 'custom_session', got %s", cookie.Name)
	}
	if cookie.Value != token {
		t.Errorf("Expected cookie value '%s', got %s", token, cookie.Value)
	}
	if cookie.Path != "/" {
		t.Errorf("Expected cookie path '/', got %s", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Error("Cookie should be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("Cookie should be Secure")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("Expected SameSite %v, got %v", http.SameSiteStrictMode, cookie.SameSite)
	}
	if cookie.MaxAge != int(config.RenewabilityTime.Seconds()) {
		t.Errorf("Expected MaxAge %d, got %d", int(config.RenewabilityTime.Seconds()), cookie.MaxAge)
	}
}

func TestAuthController_ClearSessionCookie(t *testing.T) {
	// GIVEN: Auth controller
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)

	w := httptest.NewRecorder()

	// WHEN: Clearing session cookie
	ac.ClearSessionCookie(w)

	// THEN: Should set cookie with clearing attributes
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "test_session" {
		t.Errorf("Expected cookie name 'test_session', got %s", cookie.Name)
	}
	if cookie.Value != "-" {
		t.Errorf("Expected cookie value '-', got %s", cookie.Value)
	}
	if cookie.MaxAge != 1 {
		t.Errorf("Expected MaxAge 1, got %d", cookie.MaxAge)
	}
	if !cookie.HttpOnly {
		t.Error("Clear cookie should be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("Clear cookie should be Secure")
	}
}

func TestAuthController_GetSessionFromRequest_ValidCookie(t *testing.T) {
	// GIVEN: Auth controller with valid session
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)

	token := "1234567890123456789012345678901234567890"
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          token,
		ActiveUntil:    now.Add(time.Hour),
		RenewableUntil: now.Add(24 * time.Hour),
		Revoked:        false,
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[token] = session

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "test_session", Value: token})

	// WHEN: Getting session from request
	returnedSession, found := ac.GetSessionFromRequest(r)

	// THEN: Should return valid session
	if !found {
		t.Error("Session should be found")
	}
	if returnedSession == nil {
		t.Fatal("Session should not be nil")
	}
	if returnedSession.UserID != 123 {
		t.Errorf("Expected UserID 123, got %d", returnedSession.UserID)
	}
}

func TestAuthController_GetSessionFromRequest_NoCookie(t *testing.T) {
	// GIVEN: Auth controller and request without cookie
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)

	r := httptest.NewRequest("GET", "/", nil)

	// WHEN: Getting session from request without cookie
	session, found := ac.GetSessionFromRequest(r)

	// THEN: Should return false
	if found {
		t.Error("Session should not be found")
	}
	if session != nil {
		t.Error("Session should be nil")
	}
}

func TestAuthController_GetSessionFromRequest_InvalidTokenLength(t *testing.T) {
	// GIVEN: Auth controller and request with wrong token length
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "test_session", Value: "short"})

	// WHEN: Getting session from request with invalid token
	session, found := ac.GetSessionFromRequest(r)

	// THEN: Should return false
	if found {
		t.Error("Session should not be found for invalid token length")
	}
	if session != nil {
		t.Error("Session should be nil for invalid token length")
	}
}

func TestAuthController_GetSessionFromRequest_VerificationError(t *testing.T) {
	// GIVEN: Auth controller with failing verification
	config := NewConfig("test_session")
	store := newMockSessionStore()
	store.getError = errors.New("database error")
	ac := NewAuthController(config, store)

	token := "1234567890123456789012345678901234567890"
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "test_session", Value: token})

	// WHEN: Getting session with verification error
	session, found := ac.GetSessionFromRequest(r)

	// THEN: Should return false on verification error
	if found {
		t.Error("Session should not be found on verification error")
	}
	if session != nil {
		t.Error("Session should be nil on verification error")
	}
}

func TestAuthController_GetSessionFromRequest_NilSession(t *testing.T) {
	// GIVEN: Auth controller with no matching session
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)

	token := "1234567890123456789012345678901234567890"
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "test_session", Value: token})

	// WHEN: Getting non-existent session
	session, found := ac.GetSessionFromRequest(r)

	// THEN: Should return false for nil session
	if found {
		t.Error("Session should not be found for nil session")
	}
	if session != nil {
		t.Error("Session should be nil")
	}
}

// Edge case and boundary tests

func TestAuthController_TimeCalculations(t *testing.T) {
	// GIVEN: Config with specific time durations
	config := Config{
		CookieName:         "test_session",
		SessionTokenLength: 32,
		ValidityTime:       2 * time.Hour,
		RenewabilityTime:   10 * time.Hour,
		SameSite:           http.SameSiteLaxMode,
	}
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	r := httptest.NewRequest("GET", "/", nil)
	beforeCreate := time.Now()

	// WHEN: Creating a session
	session, err := ac.CreateSession(ctx, 123, r)

	// THEN: Time calculations should be accurate
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	afterCreate := time.Now()
	expectedValidityStart := beforeCreate.Add(config.ValidityTime)
	expectedValidityEnd := afterCreate.Add(config.ValidityTime)
	expectedRenewabilityStart := beforeCreate.Add(config.RenewabilityTime)
	expectedRenewabilityEnd := afterCreate.Add(config.RenewabilityTime)

	if session.ActiveUntil.Before(expectedValidityStart) || session.ActiveUntil.After(expectedValidityEnd) {
		t.Error("ActiveUntil time calculation is outside expected range")
	}
	if session.RenewableUntil.Before(expectedRenewabilityStart) || session.RenewableUntil.After(expectedRenewabilityEnd) {
		t.Error("RenewableUntil time calculation is outside expected range")
	}
}

func TestAuthController_RenewalTimeCalculations(t *testing.T) {
	// GIVEN: Auth controller with custom config and expired session
	config := Config{
		CookieName:         "test_session",
		SessionTokenLength: 32,
		ValidityTime:       3 * time.Hour,
		RenewabilityTime:   12 * time.Hour,
		SameSite:           http.SameSiteLaxMode,
	}
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	oldToken := "1234567890123456789012345678901234567890"
	now := time.Now()
	session := &Session{
		ID:             1,
		UserID:         123,
		Token:          oldToken,
		ActiveUntil:    now.Add(-time.Hour), // Expired
		RenewableUntil: now.Add(time.Hour),  // But renewable
		Revoked:        false,
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[oldToken] = session

	beforeRenewal := time.Now()

	// WHEN: Verifying expired session (triggering renewal)
	renewedSession, renewed, err := ac.VerifySession(ctx, oldToken)

	// THEN: Renewed session should have correct time calculations
	if err != nil {
		t.Fatalf("VerifySession failed: %v", err)
	}
	if !renewed {
		t.Fatal("Session should have been renewed")
	}

	afterRenewal := time.Now()
	expectedValidityStart := beforeRenewal.Add(config.ValidityTime)
	expectedValidityEnd := afterRenewal.Add(config.ValidityTime)
	expectedRenewabilityStart := beforeRenewal.Add(config.RenewabilityTime)
	expectedRenewabilityEnd := afterRenewal.Add(config.RenewabilityTime)

	if renewedSession.ActiveUntil.Before(expectedValidityStart) || renewedSession.ActiveUntil.After(expectedValidityEnd) {
		t.Error("Renewed ActiveUntil time calculation is outside expected range")
	}
	if renewedSession.RenewableUntil.Before(expectedRenewabilityStart) || renewedSession.RenewableUntil.After(expectedRenewabilityEnd) {
		t.Error("Renewed RenewableUntil time calculation is outside expected range")
	}
}

func TestAuthController_ZeroTokenLength(t *testing.T) {
	// GIVEN: Config with zero token length (edge case)
	config := Config{
		CookieName:         "test_session",
		SessionTokenLength: 0,
		ValidityTime:       time.Hour,
		RenewabilityTime:   24 * time.Hour,
		SameSite:           http.SameSiteLaxMode,
	}
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	r := httptest.NewRequest("GET", "/", nil)

	// WHEN: Creating session with zero token length
	session, err := ac.CreateSession(ctx, 123, r)

	// THEN: Should create session with empty token
	if err != nil {
		t.Fatalf("CreateSession should handle zero token length: %v", err)
	}
	if session == nil {
		t.Fatal("Session should not be nil")
	}
	if len(session.Token) != 0 {
		t.Errorf("Expected empty token, got token of length %d", len(session.Token))
	}
}

func TestAuthController_LargeTokenLength(t *testing.T) {
	// GIVEN: Config with large token length
	config := Config{
		CookieName:         "test_session",
		SessionTokenLength: 128,
		ValidityTime:       time.Hour,
		RenewabilityTime:   24 * time.Hour,
		SameSite:           http.SameSiteLaxMode,
	}
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	r := httptest.NewRequest("GET", "/", nil)

	// WHEN: Creating session with large token length
	session, err := ac.CreateSession(ctx, 123, r)

	// THEN: Should create session with correct token length
	if err != nil {
		t.Fatalf("CreateSession should handle large token length: %v", err)
	}
	if session == nil {
		t.Fatal("Session should not be nil")
	}
	if len(session.Token) != 128 {
		t.Errorf("Expected token length 128, got %d", len(session.Token))
	}
}

func TestAuthController_SessionBoundaryTimes(t *testing.T) {
	// GIVEN: Auth controller and session at exact boundary times
	config := NewConfig("test_session")
	store := newMockSessionStore()
	ac := NewAuthController(config, store)
	ctx := context.Background()

	now := time.Now()
	token := "1234567890123456789012345678901234567890"

	// Test session expiring exactly now
	sessionExpiringNow := &Session{
		ID:             1,
		UserID:         123,
		Token:          token,
		ActiveUntil:    now,                 // Expiring exactly now
		RenewableUntil: now.Add(time.Hour),  // But renewable
		Revoked:        false,
		User:           &User{ID: 123, Login: "testuser"},
	}
	store.sessions[token] = sessionExpiringNow

	// WHEN: Verifying session expiring exactly now
	session, renewed, err := ac.VerifySession(ctx, token)

	// THEN: Should trigger renewal due to After() check
	if err != nil {
		t.Fatalf("VerifySession failed: %v", err)
	}
	if !renewed {
		t.Error("Session expiring exactly now should be renewed")
	}
	if session == nil {
		t.Error("Should return renewed session")
	}
}