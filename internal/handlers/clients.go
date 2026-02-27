package handlers

import (
	"encoding/json"
	"net/http"
	"sakura/internal/types"
	"sakura/internal/utils"

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
	json.NewDecoder(r.Body).Decode(&cp)

	var client = types.OauthClient{
		ClientID:     uuid.New(),
		Name:         cp.Name,
		ClientSecret: utils.GenerateCode(),
		RedirectURIs: cp.RedirectURIs,
		Scopes:       cp.Scope,
	}

	clients[client.ClientID.String()] = &client
	w.WriteHeader(http.StatusCreated)
	utils.WriteJson(w, client)
}
