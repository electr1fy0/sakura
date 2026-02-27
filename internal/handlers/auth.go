package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sakura/internal/types"
	"sakura/internal/utils"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ID -> User Resources
var users = make(map[string]types.User)

const baseURL = "http://localhost:8080"

type Handler struct {
}
type UserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) Signin(w http.ResponseWriter, r *http.Request) {
	rq := r.URL.Query()
	returnURL := rq.Get("return_to")
	returnU, err := url.Parse(returnURL)
	returnU.RawQuery = rq.Encode()

	fmt.Println("return url after signing:", returnU)

	var up UserPayload
	json.NewDecoder(r.Body).Decode(&up)

	var user types.User
	for _, u := range users {
		if u.Username == up.Username {
			user = u
			break
		}
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
		Name:     "sakura-jwt",
		HttpOnly: true,
		Value:    signed,
		Expires:  time.Now().Add(48 * time.Hour),
	}

	finalReturnURI := returnU.String()
	http.SetCookie(w, cookie)
	http.Redirect(w, r, finalReturnURI, http.StatusFound)
	fmt.Println("final return: ", finalReturnURI)
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var up UserPayload
	json.NewDecoder(r.Body).Decode(&up)

	hash, _ := bcrypt.GenerateFromPassword([]byte(up.Password), 10)

	user := types.User{ID: uuid.New(), Username: up.Username, PasswordHash: string(hash)}
	users[user.ID.String()] = user

	w.WriteHeader(http.StatusCreated)
}
