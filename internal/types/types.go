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

type AuthCode struct {
	UserID    uuid.UUID
	ClientID  uuid.UUID
	Scopes    []string
	ExpiresAt int64
}

type AuthRequest struct {
	ID          string
	UserID      uuid.UUID
	ClientID    uuid.UUID
	RedirectURI string
	Scopes      []string
	ExpiresAt   int64
}
