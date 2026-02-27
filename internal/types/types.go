package types

import (
	"github.com/google/uuid"
)

type OauthClient struct {
	ClientID     uuid.UUID
	Name         string
	ClientSecret string
	RedirectURIs []string
	Scopes       []string
}

type User struct {
	ID           uuid.UUID
	Username     string
	Email        string
	PasswordHash string
}

// Relates all actors together
type AuthCode struct {
	UserID    uuid.UUID
	ClientID  uuid.UUID
	Scopes    []string
	ExpiresAt int64
}

// Only to maintain context between /authorize and /authorize/approve.
// There might be better ways
type AuthRequest struct {
	ID          string
	UserID      uuid.UUID
	ClientID    uuid.UUID
	RedirectURI string
	Scopes      []string
	ExpiresAt   int64
}
