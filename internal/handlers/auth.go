package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sakura/internal/types"
	"sakura/internal/utils"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	// Using this for literally all JWTs
	// TODO: Use separate keys for client access and user access

	// ID -> Client Resources
	clients = make(map[string]*types.OauthClient)

	// ID -> User Resources
	users = make(map[string]types.User)

	// code -> Stuff it binds together
	codes = make(map[string]types.AuthCode)
)

const baseURL = "http://localhost:8080"

type Handler struct {
}
type UserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) Signin(w http.ResponseWriter, r *http.Request) {
	var up UserPayload
	json.NewDecoder(r.Body).Decode(&up)

	var user types.User

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
	http.SetCookie(w, cookie)
	utils.WriteJson(w, "sent cookies to eat")
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var up UserPayload
	json.NewDecoder(r.Body).Decode(&up)

	hash, _ := bcrypt.GenerateFromPassword([]byte(up.Password), 10)

	user := types.User{ID: uuid.New(), Username: up.Username, PasswordHash: string(hash)}
	users[user.ID.String()] = user

	utils.WriteJson(w, "user added")
	fmt.Println(users)
}
