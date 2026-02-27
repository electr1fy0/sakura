package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sakura/internal/types"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Using this for literally all JWTs
// TODO: Use separate keys for client access and user access
var secret = []byte("super-secret-key")

func WriteJson(w http.ResponseWriter, msg any) {
	json.NewEncoder(w).Encode(msg)
}

func GenerateJWT(user types.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":      user.ID,
		"exp":      time.Now().Add(48 * time.Hour).Unix(),
		"username": user.Username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func VerifyJWT(signed string) (jwt.MapClaims, bool) {
	token, err := jwt.Parse(signed, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	})

	if err != nil || !token.Valid {
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false
	}

	return claims, true
}

func GenerateCode() string {
	buf := make([]byte, 32)
	rand.Read(buf)

	return base64.URLEncoding.EncodeToString(buf)
}

func GenerateAccessToken(clientID string, scopes []string, user types.User) (string, error) {
	claims := jwt.MapClaims{
		"iss":   "sakura",
		"aud":   clientID,
		"exp":   time.Now().Add(48 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": strings.Join(scopes, " "),
	}
	for _, scope := range scopes {
		switch scope {
		case "sub":
			claims["sub"] = user.ID.String()
		case "username":
			claims["username"] = user.Username
		case "email":
			claims["email"] = user.Email
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}
