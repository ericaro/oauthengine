package oauthengine

import (
	"appengine"
	"appengine/blobstore"
	"appengine/datastore"
	"appengine/user"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/ericaro/oauthprovider"
	"github.com/gorilla/mux"
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

//NewOAuthHandler configure 'oauthRouter' to append:
//
// the three Oauth endpoints : 
//
//      /OAuthGetRequestToken
//      /OAuthAuthorizeToken
//      /OAuthGetAccessToken
//
// the receiver of the user's acknowledgement
// 
//      /OAuthTokenAuthorized
//
// cron job url to prune obsolete tokens and nonce
//
//      /cron/pruneObsolete
// 
func NewOAuthHandler(oauthRouter *mux.Router) {

	oauthRouter.HandleFunc("/OAuthGetRequestToken", serveTemporaryCredentialRequest)
	oauthRouter.HandleFunc("/OAuthAuthorizeToken", serveResourceOwnerAuthorize)
	oauthRouter.HandleFunc("/OAuthGetAccessToken", serveTokenCredentials)
	oauthRouter.HandleFunc("/OAuthTokenAuthorized", serveResourceOwnerAuthorized).Methods("POST")

	oauthRouter.HandleFunc("/cron/pruneObsolete", cronPruneObsolete)
}

type entity interface {
	Id() string
}

//OAuthCOnsumer is the entity representing the Consumer information.
type OAuthConsumer struct {
	Key    string
	Secret string
	Name   string
}

//Id computes the Id for this entity
func (o *OAuthConsumer) Id() string { return o.Key }

//OAuthNonce internal check entity, representing every single Nonce received.
//for security concern they should not be reused.
//Nevertheless, it is unpractical to keep nonce forever, so we timestamp every nonce, and
// old Nonce are pruned. (see pruneNonce function)
type OAuthNonce struct {
	Nonce                 string
	ConsumerKey, TokenKey string
	Timestamp             time.Time
}

//oauthNonceId compute the unique key for the Nonce
func oauthNonceId(consumerKey, tokenKey, nonce string) string {
	return consumerKey + tokenKey + nonce
}

type OAuthToken struct {
	Key         string
	ConsumerKey string
	Secret      string
	Verifier    string
	UserID      string
	Callback    string //the callback url
	Access      bool
	Timestamp   time.Time
}

func (o *OAuthToken) Id() string { return o.Key }

//OAuthEngine implements the oauthprovider BackendStore interface, and add some specific checker
type OAuthEngine struct {
	r *http.Request
	appengine.Context
}

func NewOAuthEngine(r *http.Request) *OAuthEngine {
	return &OAuthEngine{r, appengine.NewContext(r)}
}

//Entity Managerment methods
//#################################################################################################
//#################################################################################################

//Put
func (s *OAuthEngine) PutOAuthConsumer(u *OAuthConsumer) (err error) {
	c := s.Context
	name := OAuthConsumer_Table
	id := u.Id()
	c.Debugf("Storing %s for id= %s", name, id)
	_, err = datastore.Put(c, datastore.NewKey(c, name, id, 0, nil), u)
	return
}

func (s *OAuthEngine) GetOAuthConsumer(id string) (u *OAuthConsumer, err error) {
	c := s.Context
	u = &OAuthConsumer{}
	cname := OAuthConsumer_Table
	err = datastore.Get(c, datastore.NewKey(c, cname, id, 0, nil), u)
	return
}

func (s *OAuthEngine) PutOAuthNonce(u *OAuthNonce) (err error) {
	c := s.Context
	name := OAuthNonce_Table
	id := oauthNonceId(u.ConsumerKey, u.TokenKey, u.Nonce)
	c.Debugf("Storing %s for id= %s", name, id)
	_, err = datastore.Put(c, datastore.NewKey(c, name, id, 0, nil), u)
	return
}

func (s *OAuthEngine) GetOAuthNonce(consumerKey, tokenKey, nonce string) (u *OAuthNonce, err error) {
	c := s.Context
	u = &OAuthNonce{}
	cname := OAuthNonce_Table
	id := oauthNonceId(consumerKey, tokenKey, nonce)
	err = datastore.Get(c, datastore.NewKey(c, cname, id, 0, nil), u)
	return
}

func (s *OAuthEngine) PutOAuthToken(u *OAuthToken) (err error) {
	c := s.Context
	name := OAuthToken_Table
	id := u.Id()
	c.Debugf("Storing %s for id= %s", name, id)
	_, err = datastore.Put(c, datastore.NewKey(c, name, id, 0, nil), u)
	return
}

func (s *OAuthEngine) GetOAuthToken(tokenKey string) (u *OAuthToken, err error) {
	c := s.Context
	u = &OAuthToken{}
	cname := OAuthToken_Table
	id := tokenKey
	err = datastore.Get(c, datastore.NewKey(c, cname, id, 0, nil), u)
	return
}
func (s *OAuthEngine) DelOAuthToken(tokenKey string) (err error) {
	c := s.Context
	cname := OAuthToken_Table
	id := tokenKey
	err = datastore.Delete(c, datastore.NewKey(c, cname, id, 0, nil))
	return
}

func (s *OAuthEngine) Blobstore(content string) (key string, err error) {
	writer, err := blobstore.Create(s.Context, "text/plain")
	if err != nil {
		return "", err
	}
	_, err = fmt.Fprint(writer, content)
	if err != nil {
		return "", err
	}
	err = writer.Close()
	if err != nil {
		return
	}
	k, err := writer.Key()
	return string(k), err
}
func (s *OAuthEngine) Blobget(key string) (content string, err error) {

	reader := blobstore.NewReader(s.Context, appengine.BlobKey(key))
	c, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(c), nil
}

// this method shall be called in a cronjob
func cronPruneObsolete(w http.ResponseWriter, r *http.Request) {
	pruneObsolete(w, r, OAuthNonce_Table, time.Second) //24*time.Hour)
	pruneObsoleteToken(w, r, false, 24*time.Hour)
	pruneObsoleteToken(w, r, true, 6*30*24*time.Hour)

}

func pruneObsoleteToken(w http.ResponseWriter, r *http.Request, access bool, lifetime time.Duration) {
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
func pruneObsolete(w http.ResponseWriter, r *http.Request, kind string, lifetime time.Duration) {
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

// store methods
//#################################################################################################
//#################################################################################################

func (f *OAuthEngine) ConsumerSecret(consumer_key string) (secret string, err error) {
	consumer, err := f.GetOAuthConsumer(consumer_key)
	if err != nil {
		f.Errorf("Unknown Consumer Key: %v", err)
		return
	}
	content, err := f.Blobget(consumer.Secret)
	if err != nil {
		f.Errorf("Deleted Consumer Secret: %v", err)
		return
	}
	return content, nil
}

func (f *OAuthEngine) TokenSecret(token_key string) (secret string, err error) {
	tok, err := f.GetOAuthToken(token_key)
	if err != nil {
		return
	}
	secret = tok.Secret
	return
}

func (f *OAuthEngine) Uniqueness(nonce, consumer_key, token_key string) bool {
	_, err := f.GetOAuthNonce(consumer_key, token_key, nonce)
	if err == nil {
		return false
	} else {
		nonce := &OAuthNonce{
			Nonce:       nonce,
			ConsumerKey: consumer_key,
			TokenKey:    token_key,
			Timestamp:   time.Now(),
		}
		err = f.PutOAuthNonce(nonce)
		if err != nil {
			return false // if we failed to store the nonce, we reject the query. safety first
		}
		return true
	}
	panic("unreachable statement")
}

func (f *OAuthEngine) ValidateToken(token, consumer_key string) bool {
	t, err := f.GetOAuthToken(token)
	if err != nil {
		f.Context.Debugf("Unknown token %v (err= %v)", token, err)
		return false
	}
	// here you should be able to check more advanced policy like scope etc.
	if t.ConsumerKey == consumer_key {
		return true
	}
	return false
}

func uuidgen() string {
	uuid := new([16]byte)
	_, _ = rand.Read(uuid[:])
	uuid[8] = (uuid[8] | 0x40) & 0x7F    //set variant
	uuid[6] = (uuid[6] & 0xF) | (4 << 4) // set version
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

func (f *OAuthEngine) CreateTemporaryCredentials(consumer_key, callback string) (token_key, token_secret string) {
	tok := &OAuthToken{
		Key:         uuidgen(),
		ConsumerKey: consumer_key,
		Secret:      uuidgen(),
		Verifier:    uuidgen(),
		UserID:      "",
		Access:      false,
		Callback:    callback,
		Timestamp:   time.Now(),
	}
	f.PutOAuthToken(tok)
	return tok.Key, tok.Secret
}
func (f *OAuthEngine) CreateCredentials(consumer_key, request_token, verifier string) (token_key, token_secret string) {
	req, err := f.GetOAuthToken(request_token)
	if err != nil || req.UserID == "" || verifier != req.Verifier { // no user have been associated, marking the accceptation
		return "", "" // better have an err returned
	}

	tok := &OAuthToken{
		Key:         uuidgen(),
		ConsumerKey: consumer_key,
		Secret:      uuidgen(),
		Timestamp:   time.Now(),
		UserID:      req.UserID,
		Access:      true,
	}
	err = f.PutOAuthToken(tok)
	return tok.Key, tok.Secret
}

// extra methods

//CheckOAuthAccessToken assert that "r" is a valid token access
func (f *OAuthEngine) CheckOAuthAccessToken(w http.ResponseWriter, r *http.Request) (err error) {
	req, err := oauthprovider.NewAuthenticatedRequest(r, f)
	if err != nil {
		f.Errorf("Authentication failed: %s", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
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

func (f *OAuthEngine) CurrentUserId() (id string) {
	req, err := oauthprovider.NewAuthenticatedRequest(f.r, f) // I don't need the request so far
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

//Receive HandlerFunc that s
func serveTemporaryCredentialRequest(w http.ResponseWriter, r *http.Request) {

	f := NewOAuthEngine(r)

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
func serveTokenCredentials(w http.ResponseWriter, r *http.Request) {
	f := NewOAuthEngine(r)
	oauthprovider.NewEndPoints(f).TokenCredentials(w, r)

}

//display a human readable page with the request information, and a button to validate the request.
func serveResourceOwnerAuthorize(w http.ResponseWriter, r *http.Request) {
	//make it signin required in app.yaml
	c := appengine.NewContext(r)
	f := NewOAuthEngine(r)
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

	err = Render(w, content, "DefaultOAuthAuthorizeToken.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// now generate the html page that displays:
	// 1- the permission asked (the scope )
	// 2 - who (consumer key -> consumer identity)
	// 3 - a confirm / cancel button confirm redirect to an internal address here below

}

//Actually does create the access token, and return the callback
func serveResourceOwnerAuthorized(w http.ResponseWriter, r *http.Request) {
	//this should be called to get the acceptation
	c := appengine.NewContext(r)
	f := NewOAuthEngine(r)
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

		err = Render(w, content, "DefaultDefaultOAuthTokenAuthorized.tmpl")
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
func Render(w http.ResponseWriter, content interface{}, templates ...string) error {
	//process the templates
	t := template.Must(template.ParseFiles(templates...))
	return t.Execute(w, content)
}
