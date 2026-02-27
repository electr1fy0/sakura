package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sakura/internal/types"
	"sakura/internal/utils"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ID -> User Resources
var users = make(map[string]types.User)

type Handler struct {
}
type UserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Signin sets the session cookie for the provider's (me) user
// redirects back to return_to with original query params.
func (h *Handler) Signin(w http.ResponseWriter, r *http.Request) {
	rq := r.URL.Query()
	returnURL := rq.Get("return_to")
	returnU, err := url.Parse(returnURL)
	if err != nil || returnURL == "" {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}
	returnU.RawQuery = rq.Encode()

	var up UserPayload
	if err := json.NewDecoder(r.Body).Decode(&up); err != nil {
		http.Error(w, "invalid signin payload", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(up.Username) == "" || strings.TrimSpace(up.Password) == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}

	var user types.User
	found := false
	for _, u := range users {
		if u.Username == up.Username {
			user = u
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(up.Password))
	if err != nil {
		http.Error(w, "invalid password, mate", http.StatusUnauthorized)
		return
	}

	signed, err := utils.GenerateJWT(user)
	if err != nil {
		http.Error(w, "failed to generate token, mate", http.StatusUnauthorized)
		return
	}

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		HttpOnly: true,
		Value:    signed,
		Expires:  time.Now().Add(48 * time.Hour),
	}

	finalReturnURI := returnU.String()
	http.SetCookie(w, cookie)
	http.Redirect(w, r, finalReturnURI, http.StatusFound)
}

// Typical user signup to the provider (me).
func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var up UserPayload
	if err := json.NewDecoder(r.Body).Decode(&up); err != nil {
		http.Error(w, "invalid signup payload", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(up.Username) == "" || strings.TrimSpace(up.Password) == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(up.Password), 10)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	user := types.User{ID: uuid.New(), Username: up.Username, PasswordHash: string(hash)}
	users[user.ID.String()] = user

	w.WriteHeader(http.StatusCreated)
}
