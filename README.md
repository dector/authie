<p align="center"><img src="docs/logo.webp" width="300"></p>

# auth - Reusable Authentication Package

## Table of Contents

- [Installation](#installation)
- [Features](#features)
- [Quick Start](#quick-start)
- [Core Components](#core-components)
  - [Config](#config)
  - [Core Structs](#core-structs)
  - [Core Interfaces](#core-interfaces)
  - [AuthController](#authcontroller)
- [Implementation Guide](#implementation-guide)
  - [1. Implement SessionStore](#1-implement-sessionstore)
  - [2. Custom Auth Action Handler (Optional)](#2-custom-auth-action-handler-optional)
- [Usage Patterns](#usage-patterns)
  - [Login Handler](#login-handler)
  - [Logout Handler](#logout-handler)
  - [Getting Current User](#getting-current-user)
- [Database Schema](#database-schema)
- [Security Considerations](#security-considerations)
- [Samples](#samples)
  - [Minimal Sample](#minimal-sample)

A flexible, database-agnostic authentication package for Go web applications. This package provides session-based authentication with configurable cookie settings, session renewal, and pluggable action handlers.

## Installation

```bash
go get github.com/dector/authie
```

## Features

- **Database Agnostic**: Uses a `SessionStore` interface to work with any database/ORM.
- **Simplified Setup**: Concrete `User` and `Session` structs eliminate the need for interface boilerplate.
- **Configurable**: Cookie names, expiration times, and security settings.
- **Session Renewal**: Automatic session renewal before expiration.
- **Flexible Actions**: Pluggable handlers for auth failures (redirects, API responses, etc.).
- **Security**: Secure token generation, HTTP-only cookies, configurable SameSite.

## Quick Start

```go
package main

import "github.com/dector/authie"

func main() {
    // 1. Create configuration
    config := auth.NewConfig("my_session")

    // 2. Implement the SessionStore interface for your database
    store := NewMySessionStore(db) // Your database-specific implementation

    // 3. Create AuthController
    authController := auth.NewAuthController(config, store)

    // 4. Use in HTTP middleware
    actionHandler := auth.NewDefaultAuthActionHandler("/login")

    // For frameworks like gorilla/mux, chi, etc:
    // r.Use(authController.Middleware(actionHandler))

    // For standard library:
    // http.Handle("/protected", authController.Middleware(actionHandler)(yourHandler))
}
```

## Core Components

### Config

Configuration for session management:

```go
type Config struct {
    CookieName       string        // Required: name of session cookie
    ValidityTime     time.Duration // How long session is active
    RenewabilityTime time.Duration // How long session can be renewed
    SameSite         http.SameSite // Cookie SameSite setting
}
```

**Default Values:**
- `ValidityTime`: 3 days
- `RenewabilityTime`: 7 days
- `SameSite`: `http.SameSiteLaxMode`

### Core Structs

The package provides concrete `User` and `Session` structs, removing the need for you to implement these interfaces.

```go
// User represents the authenticated user.
type User struct {
    ID    int
    Login string
}

// Session represents a user session.
type Session struct {
    ID             int
    UserID         int
    Token          string
    ActiveUntil    time.Time
    RenewableUntil time.Time
    IPAddress      string
    Revoked        bool
    User           *User // Associated user data
}
```

### Core Interfaces

#### SessionStore Interface
You must implement this interface to provide the bridge between the `auth` package and your database.

```go
type SessionStore interface {
    CreateSession(ctx context.Context, params CreateSessionParams) (*auth.Session, error)
    GetSessionByToken(ctx context.Context, params GetSessionByTokenParams) (*auth.Session, error)
    UpdateSession(ctx context.Context, params UpdateSessionParams) error
    RevokeSession(ctx context.Context, params RevokeSessionParams) error
}
```

**Parameter Structs:**
```go
type CreateSessionParams struct {
    UserID         int
    Token          string
    ActiveUntil    time.Time
    RenewableUntil time.Time
    IPAddress      string
}

// ... other param structs (GetSessionByTokenParams, etc.)
```

#### AuthActionHandler Interface
Handles authentication failures, allowing for custom logic (e.g., API responses vs. redirects).

```go
type AuthActionHandler interface {
    HandleUnauthenticated(w http.ResponseWriter, r *http.Request)
    HandleAuthError(w http.ResponseWriter, r *http.Request, err error)
}
```

### AuthController

The main controller for session management.

```go
// Create session for a user
CreateSession(ctx context.Context, userID int, r *http.Request) (*auth.Session, error)

// Verify and optionally renew a session from a token
VerifySession(ctx context.Context, token string) (*auth.Session, bool, error)

// Close/revoke a session
CloseSession(ctx context.Context, sessionID int) error

// Set the session cookie on the response
SetSessionCookie(w http.ResponseWriter, token string)

// Clear the session cookie
ClearSessionCookie(w http.ResponseWriter)

// Get the session from an HTTP request
GetSessionFromRequest(r *http.Request) (*auth.Session, bool)

// HTTP middleware to protect routes
Middleware(actionHandler AuthActionHandler) func(http.Handler) http.Handler
```

## Implementation Guide

### 1. Implement SessionStore

The only implementation required is the `SessionStore` interface. Create an adapter for your database that maps your data models to the `auth.Session` and `auth.User` structs.

```go
import (
    "github.com/dector/authie"
    "your-project/db/models" // Your database models
)

type MySessionStore struct {
    db *sql.DB // or your ORM client
}

func (s *MySessionStore) CreateSession(ctx context.Context, params auth.CreateSessionParams) (*auth.Session, error) {
    // 1. Insert session into your database
    dbSession, err := models.CreateDBSession(ctx, s.db, params)
    if err != nil {
        return nil, err
    }

    // 2. Map your DB model to auth.Session and return
    return &auth.Session{
        ID:             dbSession.ID,
        UserID:         dbSession.UserID,
        Token:          dbSession.Token,
        ActiveUntil:    dbSession.ActiveUntil,
        RenewableUntil: dbSession.RenewableUntil,
        IPAddress:      dbSession.IPAddress,
        Revoked:        dbSession.RevokedAt != nil,
    }, nil
}

func (s *MySessionStore) GetSessionByToken(ctx context.Context, params auth.GetSessionByTokenParams) (*auth.Session, error) {
    // 1. Query session and user data from your database
    dbSession, err := models.GetDBSessionWithUser(ctx, s.db, params.Token)
    if err != nil {
        return nil, err
    }

    // 2. Map your DB models to auth.Session and auth.User
    return &auth.Session{
        ID:             dbSession.ID,
        UserID:         dbSession.UserID,
        Token:          dbSession.Token,
        ActiveUntil:    dbSession.ActiveUntil,
        RenewableUntil: dbSession.RenewableUntil,
        IPAddress:      dbSession.IPAddress,
        Revoked:        dbSession.RevokedAt != nil,
        User: &auth.User{
            ID:    dbSession.User.ID,
            Login: dbSession.User.Login,
        },
    }, nil
}

func (s *MySessionStore) UpdateSession(ctx context.Context, params auth.UpdateSessionParams) error {
    // Update session token and timestamps in your database
}

func (s *MySessionStore) RevokeSession(ctx context.Context, params auth.RevokeSessionParams) error {
    // Mark session as revoked in your database
}
```

### 2. Custom Auth Action Handler (Optional)

For API responses instead of redirects, you can implement a custom handler.

```go
type APIAuthActionHandler struct{}

func (h *APIAuthActionHandler) HandleUnauthenticated(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusUnauthorized)
    json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
}

func (h *APIAuthActionHandler) HandleAuthError(w http.ResponseWriter, r *http.Request, err error) {
    // ... handle error
}
```

## Usage Patterns

### Login Handler

```go
func LoginHandler(authController *auth.AuthController) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // ... validate credentials for 'user' ...

        // Create session
        session, err := authController.CreateSession(r.Context(), user.ID, r)
        if err != nil {
            http.Error(w, "Failed to create session", http.StatusInternalServerError)
            return
        }

        // Set cookie using the session token
        authController.SetSessionCookie(w, session.Token)

        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
    }
}
```

### Logout Handler

```go
func LogoutHandler(authController *auth.AuthController) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Optional: revoke session in database
        if session, ok := authController.GetSessionFromRequest(r); ok {
            authController.CloseSession(r.Context(), session.ID)
        }

        // Clear cookie
        authController.ClearSessionCookie(w)

        http.Redirect(w, r, "/login", http.StatusSeeOther)
    }
}
```

### Getting Current User

```go
func SomeHandler(w http.ResponseWriter, r *http.Request) {
    // User is available in context after middleware
    user, ok := r.Context().Value("user").(*auth.User)
    if !ok {
        http.Error(w, "User not found", http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "Hello, %s!", user.Login)
}
```

## Database Schema

A compatible session table structure:

```sql
CREATE TABLE user_sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token VARCHAR(40) NOT NULL UNIQUE,
    active_until TIMESTAMP NOT NULL,
    renewable_until TIMESTAMP NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_user_sessions_token ON user_sessions(token);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
```

## Security Considerations

- **Tokens**: 40-character hex tokens (160 bits of entropy)
- **Cookies**: HTTP-only, Secure, configurable SameSite
- **IP Tracking**: Sessions track IP addresses for security monitoring
- **Session Renewal**: Automatic renewal prevents session fixation
- **Revocation**: Explicit session revocation support

## Samples

### Minimal Sample

A basic setup using an in-memory store.

```go
package main

import (
    "context"
    "fmt"
    "net/http"
    "time"
    "github.com/dector/authie"
)

// In-memory representations of our data
var mockUsers = map[int]struct{ ID int; Login string }{
    1: {ID: 1, Login: "testuser"},
}
var mockSessions = make(map[string]*auth.Session)

// Minimal SessionStore implementation
type SimpleSessionStore struct{}

func (s *SimpleSessionStore) CreateSession(ctx context.Context, params auth.CreateSessionParams) (*auth.Session, error) {
    user, ok := mockUsers[params.UserID]
    if !ok {
        return nil, fmt.Errorf("user not found")
    }

    session := &auth.Session{
        ID:             len(mockSessions) + 1,
        UserID:         params.UserID,
        Token:          params.Token,
        ActiveUntil:    params.ActiveUntil,
        RenewableUntil: params.RenewableUntil,
        IPAddress:      params.IPAddress,
        User:           &auth.User{ID: user.ID, Login: user.Login},
    }
    mockSessions[params.Token] = session
    return session, nil
}

func (s *SimpleSessionStore) GetSessionByToken(ctx context.Context, params auth.GetSessionByTokenParams) (*auth.Session, error) {
    session, exists := mockSessions[params.Token]
    if !exists {
        return nil, fmt.Errorf("session not found")
    }
    return session, nil
}

func (s *SimpleSessionStore) UpdateSession(ctx context.Context, params auth.UpdateSessionParams) error {
    // Find and update session
    return nil // Simplified for example
}

func (s *SimpleSessionStore) RevokeSession(ctx context.Context, params auth.RevokeSessionParams) error {
    // Find and mark session as revoked
    return nil // Simplified for example
}

func main() {
    // Setup
    config := auth.NewConfig("simple_session")
    store := &SimpleSessionStore{}
    authController := auth.NewAuthController(config, store)
    authActionHandler := auth.NewDefaultAuthActionHandler("/login")

    mux := http.NewServeMux()

    // Login page
    mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
            session, err := authController.CreateSession(r.Context(), 1, r) // Login user 1
            if err != nil {
                http.Error(w, "Login failed", http.StatusInternalServerError)
                return
            }
            authController.SetSessionCookie(w, session.Token)
            http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
        } else {
            fmt.Fprint(w, `<form method="post"><input type="submit" value="Login"></form>`)
        }
    })

    // Protected dashboard
    dashboardHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := r.Context().Value("user").(*auth.User)
        fmt.Fprintf(w, "Welcome, %s!", user.Login)
    })
    mux.Handle("/dashboard", authController.Middleware(authActionHandler)(dashboardHandler))

    fmt.Println("Server starting on :8080")
    http.ListenAndServe(":8080", mux)
}
```
