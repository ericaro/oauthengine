package oauthengine

import (
	"appengine"
	"appengine/datastore"
	"appengine/user"
	"fmt"
	"github.com/ericaro/oauthprovider"
	"html/template"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// every "entity"'s name is declared here'
var (
	OAuthConsumer_Table = "OAuthConsumer"
	OAuthNonce_Table    = "OAuthNonce"
	OAuthToken_Table    = "OAuthToken"
)

//OauthServer is a module level object used to configure the app.
// creates a an instance of OAuthServer configure parameters and you are ready
type OAuthServer struct{}

//note: in go1.1  methods are top level functions too, so I guess this piece of code should be simpler
func (s *OAuthServer) OAuthGetRequestToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.serveTemporaryCredentialRequest(w, r) }
}

func (s *OAuthServer) OAuthAuthorizeToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.serveResourceOwnerAuthorize(w, r) }
}
func (s *OAuthServer) OAuthGetAccessToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.serveTokenCredentials(w, r) }
}
func (s *OAuthServer) OAuthTokenAuthorized() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.serveResourceOwnerAuthorized(w, r) }
}
func (s *OAuthServer) PruneObsolete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.cronPruneObsolete(w, r) }
}

// this method shall be called in a cronjob
func (s *OAuthServer) cronPruneObsolete(w http.ResponseWriter, r *http.Request) {
	s.pruneObsolete(w, r, OAuthNonce_Table, time.Second) //24*time.Hour)
	s.pruneObsoleteToken(w, r, false, 24*time.Hour)
	s.pruneObsoleteToken(w, r, true, 6*30*24*time.Hour)

}

func (*OAuthServer) pruneObsoleteToken(w http.ResponseWriter, r *http.Request, access bool, lifetime time.Duration) {
	c := appengine.NewContext(r)
	keys, err := datastore.NewQuery(OAuthToken_Table).
		Filter("Timestamp <", time.Now().Add(lifetime)).
		Filter("Access =", access).
		KeysOnly().
		GetAll(c, nil)
	if err != nil {
		c.Debugf("Error in pruning Token (Access=%v): %v", access, err)
		return
	}
	datastore.DeleteMulti(c, keys)
}

//prune any entity with a Timestamp field, older that the "lieftime" duration
func (*OAuthServer) pruneObsolete(w http.ResponseWriter, r *http.Request, kind string, lifetime time.Duration) {
	c := appengine.NewContext(r)
	keys, err := datastore.NewQuery(kind).
		Filter("Timestamp <", time.Now().Add(lifetime)).
		KeysOnly().
		GetAll(c, nil)
	if err != nil {
		c.Debugf("Error in pruning %s: %v", kind, err)
		return
	}
	datastore.DeleteMulti(c, keys)
}

// extra methods

//Receive HandlerFunc that s
func (*OAuthServer) serveTemporaryCredentialRequest(w http.ResponseWriter, r *http.Request) {

	f := NewBackendStore(r)

	// 
	ur := oauthprovider.ParsingRequest(r, f)
	f.Debugf("URL  %s:", r.URL.String())
	f.Debugf("Host  %s:", r.Host)
	f.Debugf("Basestring %s:", ur.SignatureBaseString())

	f.Debugf("Headers:")
	for _, h := range strings.Split(r.Header.Get("Authorization"), ",") {

		f.Debugf(h)
	}

	// c := appengine.NewContext(r)
	// c.Debugf("received\n%s %s http/1.1\nAuthorization %s\n", r.Method, r.URL.String(), r.Header.Get("Authorization"))
	oauthprovider.NewEndPoints(f).TemporaryCredentialRequest(w, r)
}
func (*OAuthServer) serveTokenCredentials(w http.ResponseWriter, r *http.Request) {
	f := NewBackendStore(r)
	oauthprovider.NewEndPoints(f).TokenCredentials(w, r)

}

//display a human readable page with the request information, and a button to validate the request.
func (s *OAuthServer) serveResourceOwnerAuthorize(w http.ResponseWriter, r *http.Request) {
	//make it signin required in app.yaml
	c := appengine.NewContext(r)
	f := NewBackendStore(r)
	u := user.Current(c)
	if u == nil {
		login, err := user.LoginURL(c, r.URL.String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, login, http.StatusFound)
		return
	}
	token_key := r.URL.Query().Get("oauth_token")
	token, err := f.GetOAuthToken(token_key)
	consumer, err := f.GetOAuthConsumer(token.ConsumerKey)

	content := struct {
		Token    *OAuthToken
		Consumer *OAuthConsumer
	}{token, consumer}

	err = s.Render(w, content, "DefaultOAuthAuthorizeToken.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// now generate the html page that displays:
	// 1- the permission asked (the scope )
	// 2 - who (consumer key -> consumer identity)
	// 3 - a confirm / cancel button confirm redirect to an internal address here below

}

//Actually does create the access token, and return the callback
func (s *OAuthServer) serveResourceOwnerAuthorized(w http.ResponseWriter, r *http.Request) {
	//this should be called to get the acceptation
	c := appengine.NewContext(r)
	f := NewBackendStore(r)
	u := user.Current(c)
	if u == nil {
		http.Error(w, "Login Required to access this page", http.StatusUnauthorized)
		return
	}

	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if content != "application/x-www-form-urlencoded" {
		http.Error(w, fmt.Sprintf("Invalid Content Type: %s instead of application/x-www-form-urlencoded", content), http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close() // caveat this means that the body is no longer readable
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vals, err := url.ParseQuery(string(body))

	tokenKey := vals.Get("oauth_token")
	tokenVerifier := vals.Get("oauth_verifier") // Yes I require that the "confirm" form contains the verifier so that a client cannot send user to this url and they validate the permission by just logging in
	token, err := f.GetOAuthToken(tokenKey)
	if token.Verifier != tokenVerifier {
		http.Error(w, "Invalid Verifier.", http.StatusForbidden)
		return
	}

	token.UserID = u.ID    // that is the way to acknowledge the permission (in the request token)
	f.PutOAuthToken(token) // and store it.

	// now either redirect the user, or display the verifier code
	if token.Callback == "" || token.Callback == "oob" {
		// display the "confirmed, please copy paste the "verification code" page 
		content := struct {
			Token *OAuthToken
		}{token}

		err = s.Render(w, content, "DefaultDefaultOAuthTokenAuthorized.tmpl")
		return
	} else {
		redirectURL, err := url.Parse(token.Callback)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		q := redirectURL.Query()
		q.Set("oauth_token", tokenKey)
		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
		return
	}
}

//Basic template based renderer
func (*OAuthServer) Render(w http.ResponseWriter, content interface{}, templates ...string) error {
	//process the templates
	t := template.Must(template.ParseFiles(templates...))
	return t.Execute(w, content)
}
