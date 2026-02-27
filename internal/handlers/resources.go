package handlers

import (
	"net/http"
	"sakura/internal/utils"
	"strings"
)

func (h *Handler) Protected(w http.ResponseWriter, r *http.Request) {
	utils.WriteJson(w, "you are in my guy")
}

// Resource verifies the bearer token and returns token claims as JSON.
func (h *Handler) Resource(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authz, "Bearer ")
	claims, ok := utils.VerifyJWT(token)
	if !ok {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	utils.WriteJson(w, claims)
}
