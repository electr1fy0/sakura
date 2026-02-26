package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const baseURL = "http://localhost:8080"

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

// ID is the key for now
var users = make(map[string]User)

func isURIAllowed(client *Client, uri string) bool {
	if slices.Contains(client.RedirectURIs, uri) {
		return true
	}
	return false
}

var secret = []byte("super-secret-key")

func (h *Handler) Signin(w http.ResponseWriter, r *http.Request) {
	var up UserPayload
	json.NewDecoder(r.Body).Decode(&up)

	var user User

	for _, u := range users {
		if u.Username == up.Username {
			user = u
			break
		}
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(up.Password))
	if err != nil {
		http.Error(w, "invalid password, mate", http.StatusUnauthorized)
		return
	}

	signed, err := generateJWT(user)
	if err != nil {
		http.Error(w, "failed to generate token, mate", http.StatusUnauthorized)
		return
	}

	cookie := &http.Cookie{
		Name:     "sakura-jwt",
		HttpOnly: true,
		Value:    signed,
		Expires:  time.Now().Add(48 * time.Hour),
	}
	http.SetCookie(w, cookie)
	writeJson(w, "sent cookies to eat")
}

type UserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var up UserPayload
	json.NewDecoder(r.Body).Decode(&up)

	hash, _ := bcrypt.GenerateFromPassword([]byte(up.Password), 10)

	user := User{ID: uuid.New(), Username: up.Username, PasswordHash: string(hash)}
	users[user.ID.String()] = user

	writeJson(w, "user added")
	fmt.Println(users)
}

func writeJson(w http.ResponseWriter, msg any) {
	json.NewEncoder(w).Encode(msg)
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
	// clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	// TODO: implement other types later
	_ = r.URL.Query().Get("response_type")

	// client, ok := clients[clientID]
	// if !ok {
	// 	http.Error(w, "client does not exist", http.StatusUnauthorized)
	// 	return
	// }

	// if !isURIAllowed(client, redirectURI) {
	// 	http.Error(w, "redirect uri is not allowed", http.StatusUnauthorized)
	// 	return
	// }
	code := generateCode()

	callbackURI, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect uri", http.StatusBadRequest)
		return
	}
	q := callbackURI.Query()
	q.Set("code", code)
	callbackURI.RawQuery = q.Encode()

	http.Redirect(w, r, callbackURI.String(), http.StatusFound)

}

// base64 does chunking of each byte to 6 bits each
// therefore we do 4/3 as byte count taken
func generateCode() string {
	buf := make([]byte, 32)
	rand.Read(buf)

	var encoded = make([]byte, 44)
	base64.URLEncoding.Encode(encoded, buf)

	return string(encoded)
}

func VerifySession(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("sakura-jwt")
		if err != nil {
			http.Redirect(w, r, baseURL+"/signin", http.StatusTemporaryRedirect)
			return
		}

		token := cookie.Value
		claims, ok := verifyJWT(token)
		if !ok {
			http.Redirect(w, r, baseURL+"/signin", http.StatusTemporaryRedirect)
			return
		}
		fmt.Println(claims["username"])
		next.ServeHTTP(w, r)
	})
}

// RBAC: Role based access control
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	// grantType := r.URL.Query().Get("grant_type")
	// code := r.URL.Query().Get("code")
	// clientID := r.URL.Query().Get("client_id")
	// clientSecret := r.URL.Query().Get("client_secret")

	// TODO
	// verifySecret()
	// verifyCode()
	// deleteCode()

	token, err := generateAccessToken()
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "%s", token)
}

func generateAccessToken() (string, error) {
	claims := jwt.MapClaims{
		"iss":   "sakura",
		"sub":   "user_meow",
		"aud":   "client-id",
		"exp":   time.Now().Add(48 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "openid profile email projects: read",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}

func (h *Handler) Protected(w http.ResponseWriter, r *http.Request) {
	writeJson(w, "you are in my guy")
}

func main() {
	r := chi.NewRouter()
	h := Handler{}

	r.Post("/signup", h.Signup)
	r.Post("/signin", h.Signin)
	r.Get("/protected", VerifySession(h.Protected))
	r.Get("/authorize", VerifySession(h.Authorize))
	r.Get("/token", h.Token)

	server := http.Server{
		Handler: r,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
