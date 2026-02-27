package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"sakura/internal/types"
	"sakura/internal/utils"
	"slices"

	"github.com/google/uuid"
)

var (
	// code -> Stuff it binds together
	codes = make(map[string]types.AuthCode)
)

func VerifyRedirect(c *types.OauthClient, uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	return false
}

func BuildSigninURL(rq *url.Values) (string, error) {
	signinStr := baseURL + "/signin"
	signinURL, err := url.Parse(signinStr)
	if err != nil {
		return "", err
	}
	signinURL.RawQuery = rq.Encode()
	fmt.Println("signin url: ", signinURL.String())
	return signinURL.String(), nil
}

// Authorize generates a code
// and redirects to the callback URI
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	rq := r.URL.Query()
	clientID := rq.Get("client_id")
	redirectURI := rq.Get("redirect_uri")
	// TODO: implement other types later
	_ = rq.Get("response_type")

	client, ok := clients[clientID]
	if !ok {
		http.Error(w, "client does not exist", http.StatusUnauthorized)
		return
	}

	// Check client's allowed redirect urls
	if !VerifyRedirect(client, redirectURI) {
		http.Error(w, "redirect uri is not allowed", http.StatusUnauthorized)
		return
	}

	rq.Set("return_to", "http://localhost:8080/authorize")
	signinURL, _ := BuildSigninURL(&rq)

	cookie, err := r.Cookie("sakura-jwt")
	if err != nil {
		http.Redirect(w, r, signinURL, http.StatusTemporaryRedirect)
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

	code := utils.GenerateCode()
	codes[code] = types.AuthCode{
		UserID:   id,
		ClientID: client.ClientID,
	}

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

func VerifySession(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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

	token, err := utils.GenerateAccessToken()
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "%s", token)
}
