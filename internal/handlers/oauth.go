package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"sakura/internal/types"
	"sakura/internal/utils"
	"slices"
	"time"

	"github.com/google/uuid"
)

var (
	// code -> authorization context
	codes        = make(map[string]types.AuthCode)
	authRequests = make(map[string]types.AuthRequest)
)

func RedirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, code string) {
	callbackURI, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect uri", http.StatusBadRequest)
		return
	}
	q := callbackURI.Query()
	q.Set("error", code)
	callbackURI.RawQuery = q.Encode()
	http.Redirect(w, r, callbackURI.String(), http.StatusFound)
}

func VerifyRedirect(c *types.OauthClient, uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	return false
}

func BuildSigninURL(rq *url.Values) (string, error) {
	signinStr := serverBaseURL() + "/signin"
	signinURL, err := url.Parse(signinStr)
	if err != nil {
		return "", err
	}
	signinURL.RawQuery = rq.Encode()
	return signinURL.String(), nil
}

// Authorize validates request and creates an auth request context.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	rq := r.URL.Query()
	clientID := rq.Get("client_id")
	redirectURI := rq.Get("redirect_uri")
	responseType := rq.Get("response_type")
	scopes := rq["scopes"]

	client, ok := clients[clientID]
	if !ok {
		http.Error(w, "client does not exist", http.StatusUnauthorized)
		return
	}
	for _, scope := range scopes {
		if !slices.Contains(client.Scopes, scope) {
			http.Error(w, "invalid scope requested", http.StatusUnauthorized)
			return
		}
	}

	if !VerifyRedirect(client, redirectURI) {
		http.Error(w, "redirect uri is not allowed", http.StatusUnauthorized)
		return
	}
	if responseType != "code" {
		RedirectOAuthError(w, r, redirectURI, "unsupported_response_type")
		return
	}

	rq.Set("return_to", serverBaseURL()+"/authorize")
	signinURL, err := BuildSigninURL(&rq)
	if err != nil {
		http.Error(w, "failed to build signin redirect", http.StatusInternalServerError)
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Redirect(w, r, signinURL, http.StatusTemporaryRedirect)
		return
	}

	token := cookie.Value
	claims, claimsOK := utils.VerifyJWT(token)
	userID, idOk := claims["sub"].(string)
	if !claimsOK || !idOk {
		http.Error(w, "failed to read user from token", http.StatusInternalServerError)
		return
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		http.Error(w, "failed to parse user's uuid", http.StatusInternalServerError)
		return
	}

	reqID := utils.GenerateCode()
	if reqID == "" {
		http.Error(w, "failed to create auth request", http.StatusInternalServerError)
		return
	}
	authRequests[reqID] = types.AuthRequest{
		ID:          reqID,
		UserID:      id,
		ClientID:    client.ClientID,
		RedirectURI: redirectURI,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
	}

	utils.WriteJson(w, map[string]any{
		"auth_request_id":  reqID,
		"client_id":        client.ClientID.String(),
		"requested_scopes": scopes,
	})
}

// AuthorizeApprove finalizes user-selected scopes and issues the auth code.
func (h *Handler) AuthorizeApprove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	reqID := r.Form.Get("auth_request_id")
	if reqID == "" {
		http.Error(w, "missing auth_request_id", http.StatusBadRequest)
		return
	}
	authReq, exists := authRequests[reqID]
	if !exists {
		http.Error(w, "invalid auth_request_id", http.StatusBadRequest)
		return
	}
	if time.Now().Unix() > authReq.ExpiresAt {
		delete(authRequests, reqID)
		RedirectOAuthError(w, r, authReq.RedirectURI, "invalid_request")
		return
	}

	scopes := r.Form["scopes"]

	client, ok := clients[authReq.ClientID.String()]
	if !ok {
		http.Error(w, "client does not exist", http.StatusUnauthorized)
		return
	}
	for _, scope := range scopes {
		if !slices.Contains(client.Scopes, scope) {
			http.Error(w, "invalid scope requested", http.StatusUnauthorized)
			return
		}
	}

	if len(scopes) == 0 {
		delete(authRequests, reqID)
		RedirectOAuthError(w, r, authReq.RedirectURI, "access_denied")
		return
	}
	for _, scope := range scopes {
		if !slices.Contains(authReq.Scopes, scope) {
			delete(authRequests, reqID)
			RedirectOAuthError(w, r, authReq.RedirectURI, "invalid_scope")
			return
		}
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Error(w, "user not authenticated", http.StatusUnauthorized)
		return
	}

	token := cookie.Value
	claims, ok := utils.VerifyJWT(token)
	userID, idOk := claims["sub"].(string)
	if !ok || !idOk {
		http.Error(w, "failed to read user from token", http.StatusInternalServerError)
		return
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		http.Error(w, "failed to parse user's uuid", http.StatusInternalServerError)
		return
	}
	if id != authReq.UserID {
		delete(authRequests, reqID)
		RedirectOAuthError(w, r, authReq.RedirectURI, "access_denied")
		return
	}

	code := utils.GenerateCode()
	if code == "" {
		http.Error(w, "failed to create auth code", http.StatusInternalServerError)
		return
	}
	codes[code] = types.AuthCode{
		UserID:   id,
		ClientID: client.ClientID,
		Scopes:   scopes,
	}
	delete(authRequests, reqID)

	callbackURI, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect uri", http.StatusBadRequest)
		return
	}

	q := callbackURI.Query()
	q.Set("code", code)
	callbackURI.RawQuery = q.Encode()

	http.Redirect(w, r, callbackURI.String(), http.StatusFound)
}

// Token exchanges an auth code for an access token.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	clientID := r.URL.Query().Get("client_id")
	clientSecret := r.URL.Query().Get("client_secret")

	client, ok := clients[clientID]

	if !ok || client.ClientSecret != clientSecret {
		http.Error(w, "invalid client creds", http.StatusUnauthorized)
		return
	}

	authCode, codeOK := codes[code]
	if !codeOK {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	authCodeUser, userOK := users[authCode.UserID.String()]
	if !userOK {
		http.Error(w, "invalid code user", http.StatusUnauthorized)
		return
	}

	authCodeClient, clientOK := clients[authCode.ClientID.String()]
	if !clientOK || authCodeClient.ClientID != client.ClientID {
		http.Error(w, "unexpected client", http.StatusUnauthorized)
		return
	}

	token, err := utils.GenerateAccessToken(client.ClientID.String(), authCode.Scopes, authCodeUser)
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}
	delete(codes, code)

	// Client uses this token to access my resources
	// The browser never sees it, ideally of course
	// but that's not really my concern.
	fmt.Fprintf(w, "%s", token)
}
