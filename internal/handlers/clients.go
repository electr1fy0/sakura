package handlers

import (
	"encoding/json"
	"net/http"
	"sakura/internal/types"
	"sakura/internal/utils"
	"strings"

	"github.com/google/uuid"
)

// ID -> Client Resources
var clients = make(map[string]*types.OauthClient)

type ClientPayLoad struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scope        []string `json:"scope"`
}

func (h *Handler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var cp ClientPayLoad
	if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
		http.Error(w, "invalid client payload", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(cp.Name) == "" || len(cp.RedirectURIs) == 0 {
		http.Error(w, "name and redirect_uris are required", http.StatusBadRequest)
		return
	}

	var client = types.OauthClient{
		ClientID:     uuid.New(),
		Name:         cp.Name,
		ClientSecret: utils.GenerateCode(),
		RedirectURIs: cp.RedirectURIs,
		Scopes:       cp.Scope,
	}
	if client.ClientSecret == "" {
		http.Error(w, "failed to generate client secret", http.StatusInternalServerError)
		return
	}

	clients[client.ClientID.String()] = &client
	w.WriteHeader(http.StatusCreated)
	utils.WriteJson(w, client)
}
