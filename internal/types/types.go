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
	PasswordHash string
}

type AuthCode struct {
	UserID    uuid.UUID
	ClientID  uuid.UUID
	ExpiresAt int64
}
