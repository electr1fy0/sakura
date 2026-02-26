package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Handler struct {
}

type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
}

type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
}

var clients = make(map[string]*Client)
var users = make(map[string]*User)

func isURIAllowed(client *Client, uri string) bool {
	if slices.Contains(client.RedirectURIs, uri) {
		return true
	}
	return false
}

var secret = []byte("super-secret-key")

func (h *Handler) Signin(w http.ResponseWriter, r *http.Request) {

}

type UserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var up UserPayload
	json.NewDecoder(r.Body).Decode(&up)

}
func generateJWT(user User) (string, error) {
	claims := jwt.MapClaims{
		"sub":      user.ID,
		"exp":      time.Now().Add(48 * time.Hour).Unix(),
		"username": user.Username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func verifyJWT(signed string) (jwt.MapClaims, bool) {
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

// Authorize generates a code
// and redirects to the callback URI
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")

	// TODO: implement other types later
	_ = r.URL.Query().Get("response_type")

	client, ok := clients[clientID]
	if !ok {
		http.Error(w, "client does not exist", http.StatusUnauthorized)
		return
	}

	if !isURIAllowed(client, redirectURI) {
		http.Error(w, "redirect uri is not allowed", http.StatusUnauthorized)
		return
	}
}

func main() {
	r := chi.NewRouter()
	h := Handler{}

	r.Post("/signup", h.Signup)
	r.Post("/login", h.Signin)
	server := http.Server{
		Handler: r,
		Addr:    ":8080",
	}

	server.ListenAndServe()

}
