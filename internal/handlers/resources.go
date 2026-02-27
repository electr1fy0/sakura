package handlers

import (
	"net/http"
	"sakura/internal/utils"
	"strings"
)

func (h *Handler) Protected(w http.ResponseWriter, r *http.Request) {
	utils.WriteJson(w, "you are in my guy")
}

// Resource returns user profile data based on granted scopes.
func (h *Handler) Resource(w http.ResponseWriter, r *http.Request) {
	const requiredScope = "profile:read"

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
	scopeClaim, scopeOK := claims["scope"].(string)
	if !scopeOK {
		w.WriteHeader(http.StatusForbidden)
		utils.WriteJson(w, map[string]string{
			"error": "invalid_scope",
		})
		return
	}

	sub, subOK := claims["sub"].(string)
	if !subOK || sub == "" {
		http.Error(w, "invalid access token subject", http.StatusUnauthorized)
		return
	}

	u, userOK := users[sub]
	if !userOK {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	user := map[string]any{
		"sub": u.ID.String(),
	}
	for scope := range strings.FieldsSeq(scopeClaim) {
		switch scope {
		case "username":
			user["username"] = u.Username
		case "email":
			user["email"] = u.Email
		case "full_name":
			user["full_name"] = u.FullName
		case "role":
			user["role"] = u.Role
		}
	}

	utils.WriteJson(w, user)
}
