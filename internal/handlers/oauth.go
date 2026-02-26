package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"sakura/internal/types"
	"sakura/internal/utils"
	"slices"
)

func IsURIAllowed(c *types.OauthClient, uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	return false
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
	code := utils.GenerateCode()

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
		cookie, err := r.Cookie("sakura-jwt")
		if err != nil {
			http.Redirect(w, r, baseURL+"/signin", http.StatusTemporaryRedirect)
			return
		}

		token := cookie.Value
		claims, ok := utils.VerifyJWT(token)
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

	token, err := utils.GenerateAccessToken()
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "%s", token)
}
