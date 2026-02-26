package types

import (
	"github.com/google/uuid"
)

type OauthClient struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
}

type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
}

type AuthCode struct {
	UserID    uuid.UUID
	ClientID  uuid.UUID
	Scopes    []string
	ExpiresAt int64
}
