//oauthengine is a google-app-engine-backed oauth service provider implementation.
//
// It relies on github.com/ericaro/oauthprovider as the main implementation of oauth on the server side.
//
//Usage:
//
// creates an OAuthServer instance
// 
// this server can be configured, and then it exposes Endpoints as "http.HandlerFunc". It's your job to connect those endpoints to a path on you server.
// 
// finally just call CheckOAuthAccessToken(r) whenever you need to check the current OAuthentication, or CurrentUserId whenever you need to know the current authtenticated user.
package oauthengine

import (
	"errors"
	"github.com/ericaro/oauthprovider"
	"net/http"
)

//CheckOAuthAccessToken assert that "r" is a valid token, a valid access token one. Return err otherwise.
func CheckOAuthAccessToken(r *http.Request) (err error) {
	f := NewBackendStore(r)
	req, err := oauthprovider.NewAuthenticatedRequest(r, f)
	if err != nil {
		return
	}
	token, _ := req.GetToken()
	tok, err := f.GetOAuthToken(token)
	if err != nil {
		return
	}
	if !tok.Access {
		return errors.New("Illegal Access token. The token has not been granted access permission")
	}
	// here I can add some extra check (like the scope and so on)
	return
}

//CurrentUserId extract from the given request the current user ID. 
func CurrentUserId(r *http.Request) (id string) {
	f := NewBackendStore(r)
	req, err := oauthprovider.NewAuthenticatedRequest(f.r, f)
	if err != nil {
		return
	}
	token, _ := req.GetToken()
	tok, err := f.GetOAuthToken(token)
	if err != nil {
		return
	}
	return tok.UserID
}
