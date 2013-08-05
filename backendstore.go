package oauthengine

import (
	"appengine"
	"appengine/blobstore"
	"appengine/datastore"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

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

//GAEBackendStore implements the oauthprovider BackendStore interface, and add some specific checker
type GAEBackendStore struct {
	r *http.Request
	appengine.Context
}

func NewGAEBackendStore(r *http.Request) *GAEBackendStore {
	return &GAEBackendStore{r, appengine.NewContext(r)}
}

//Entity Management methods
//#################################################################################################
//#################################################################################################

//Put
func (s *GAEBackendStore) PutOAuthConsumer(u *OAuthConsumer) (err error) {
	c := s.Context
	name := OAuthConsumer_Table
	id := u.Id()
	c.Debugf("Storing %s for id= %s", name, id)
	_, err = datastore.Put(c, datastore.NewKey(c, name, id, 0, nil), u)
	return
}

func (s *GAEBackendStore) GetOAuthConsumer(id string) (u *OAuthConsumer, err error) {
	c := s.Context
	u = &OAuthConsumer{}
	cname := OAuthConsumer_Table
	err = datastore.Get(c, datastore.NewKey(c, cname, id, 0, nil), u)
	return
}

func (s *GAEBackendStore) PutOAuthNonce(u *OAuthNonce) (err error) {
	c := s.Context
	name := OAuthNonce_Table
	id := oauthNonceId(u.ConsumerKey, u.TokenKey, u.Nonce)
	c.Debugf("Storing %s for id= %s", name, id)
	_, err = datastore.Put(c, datastore.NewKey(c, name, id, 0, nil), u)
	return
}

func (s *GAEBackendStore) GetOAuthNonce(consumerKey, tokenKey, nonce string) (u *OAuthNonce, err error) {
	c := s.Context
	u = &OAuthNonce{}
	cname := OAuthNonce_Table
	id := oauthNonceId(consumerKey, tokenKey, nonce)
	err = datastore.Get(c, datastore.NewKey(c, cname, id, 0, nil), u)
	return
}

func (s *GAEBackendStore) PutOAuthToken(u *OAuthToken) (err error) {
	c := s.Context
	name := OAuthToken_Table
	id := u.Id()
	c.Debugf("Storing %s for id= %s", name, id)
	_, err = datastore.Put(c, datastore.NewKey(c, name, id, 0, nil), u)
	return
}

func (s *GAEBackendStore) GetOAuthToken(tokenKey string) (u *OAuthToken, err error) {
	c := s.Context
	u = &OAuthToken{}
	cname := OAuthToken_Table
	id := tokenKey
	err = datastore.Get(c, datastore.NewKey(c, cname, id, 0, nil), u)
	return
}
func (s *GAEBackendStore) DelOAuthToken(tokenKey string) (err error) {
	c := s.Context
	cname := OAuthToken_Table
	id := tokenKey
	err = datastore.Delete(c, datastore.NewKey(c, cname, id, 0, nil))
	return
}

func (s *GAEBackendStore) Blobstore(content string) (key string, err error) {
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
func (s *GAEBackendStore) Blobget(key string) (content string, err error) {

	reader := blobstore.NewReader(s.Context, appengine.BlobKey(key))
	c, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(c), nil
}

// store methods
//#################################################################################################
//#################################################################################################

func (f *GAEBackendStore) ConsumerSecret(consumer_key string) (secret string, err error) {
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

func (f *GAEBackendStore) TokenSecret(token_key string) (secret string, err error) {
	tok, err := f.GetOAuthToken(token_key)
	if err != nil {
		return
	}
	secret = tok.Secret
	return
}

func (f *GAEBackendStore) Uniqueness(nonce, consumer_key, token_key string) bool {
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

func (f *GAEBackendStore) ValidateToken(token, consumer_key string) bool {
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

func (f *GAEBackendStore) CreateTemporaryCredentials(consumer_key, callback string) (token_key, token_secret string) {
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
func (f *GAEBackendStore) CreateCredentials(consumer_key, request_token, verifier string) (token_key, token_secret string) {
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
