package oauth2

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/arianvp/auth/jwt"
)

type AccessToken struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   []string `json:"aud"`
	JWTID      string   `json:"jti"`
	Expiration int64    `json:"exp"`
	IssuedAt   int64    `json:"iat"`
	// Confirmation jwt.Confirmation `json:"cnf"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

func (t *AccessToken) Type() string {
	return "jwt+at"
}

type IDToken struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   []string `json:"aud"`
	JWTID      string   `json:"jti"`
	Expiration int64    `json:"exp"`
	IssuedAt   int64    `json:"iat"`
}

func (t *IDToken) Type() string {
	return "jwt+id_token"
}

// TokenError is a JSON response for an error in the token endpoint as per
// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
type TokenError struct {
	Name        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("%s: %s", e.Name, e.Description)
}

func (e *TokenError) RespondJSON(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(e)
}

var (
	ErrInvalidRequest       = &TokenError{Name: "invalid_request", Description: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."}
	ErrInvalidClient        = &TokenError{Name: "invalid_client", Description: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."}
	ErrInvalidGrant         = &TokenError{Name: "invalid_grant", Description: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."}
	ErrUnauthorizedClient   = &TokenError{Name: "unauthorized_client", Description: "The authenticated client is not authorized to use this authorization grant type."}
	ErrUnsupportedGrantType = &TokenError{Name: "unsupported_grant_type", Description: "The authorization grant type is not supported by the authorization server."}
	ErrInvalidScope         = &TokenError{Name: "invalid_scope", Description: "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner."}
)

type state struct {
	redirectURI   string
	codeChallenge string
}

type codeCache struct {
	codes map[string]*state
	lock  sync.Mutex
}

func (c *codeCache) add(code string, state *state) {
	c.lock.Lock()
	c.codes[code] = state
	c.lock.Unlock()
}

func (c *codeCache) del(code string) *state {
	c.lock.Lock()
	state := c.codes[code]
	delete(c.codes, code)
	c.lock.Unlock()
	return state
}

type TokenResource struct {
	codeCache    *codeCache
	privateKey   crypto.Signer
	privateKeyId string
	origin       string
}

type TokenRequest struct {
	Code         string
	CodeVerifier string
	GrantType    string
	RedirectURI  string
	ClientID     string
}

type TokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func TokenRequestFromValues(values url.Values) TokenRequest {
	return TokenRequest{
		Code:         values.Get("code"),
		CodeVerifier: values.Get("code_verifier"),
		GrantType:    values.Get("grant_type"),
		RedirectURI:  values.Get("redirect_uri"),
		ClientID:     values.Get("client_id"),
	}
}

func ParseTokenRequest(req *http.Request) TokenRequest {
	req.ParseForm()
	return TokenRequestFromValues(req.Form)
}
func CreateCodeChallenge(codeVerifier string) (codeChallenge string) {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return
}

func VerifyCodeChallenge(codeChallenge, codeVerifier string) error {
	expectedChallenge := CreateCodeChallenge(codeVerifier)
	if codeChallenge != expectedChallenge {
		return fmt.Errorf("expected %s but got %s", expectedChallenge, codeChallenge)
	}
	return nil
}

func (t *TokenResource) handleAuthorizationCode(req TokenRequest) (*TokenResponse, error) {

	state := t.codeCache.del(req.Code)
	if state == nil {
		ErrInvalidGrant := errors.New("invalid_grant")
		return nil, ErrInvalidGrant
	}

	if err := VerifyCodeChallenge(state.codeChallenge, req.CodeVerifier); err != nil {
		return nil, ErrInvalidRequest
	}

	if req.RedirectURI != state.redirectURI {
		return nil, ErrInvalidRequest
	}

	if req.ClientID != state.redirectURI {
		ErrUnauthorizedClient := errors.New("unauthorized_client")
		return nil, ErrUnauthorizedClient
	}

	now := time.Now()

	rawSubject := make([]byte, 32)
	if _, err := rand.Read(rawSubject); err != nil {
		return nil, err
	}

	subject := base64.RawURLEncoding.EncodeToString(rawSubject)

	rawJTI := make([]byte, 32)
	if _, err := rand.Read(rawJTI); err != nil {
		return nil, err
	}

	jti := base64.RawURLEncoding.EncodeToString(rawJTI)

	accessTokenEpiresIn := now.Add(10 * time.Minute)

	at := &AccessToken{
		Issuer:     t.origin,
		Subject:    subject,
		Audience:   []string{t.origin}, // TODO: Should match the audience of the scope, _or_ the `resource` parameter
		Expiration: accessTokenEpiresIn.Unix(),
		IssuedAt:   now.Unix(),
		JWTID:      jti,
	}

	accessToken, err := jwt.EncodeAndSign(at, t.privateKeyId, t.privateKey)
	if err != nil {
		panic(err)
	}

	if _, err := rand.Read(rawJTI); err != nil {
		panic(err)
	}
	jti = base64.RawURLEncoding.EncodeToString(rawJTI)
	tokenResponse := TokenResponse{
		IDToken:     "",
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessTokenEpiresIn.Unix(),
	}
	return &tokenResponse, nil
}

func (t *TokenResource) handle(tokenRequest TokenRequest) (*TokenResponse, error) {
	switch tokenRequest.GrantType {
	case "authorization_code":
		return t.handleAuthorizationCode(tokenRequest)
	default:
		return nil, ErrUnsupportedGrantType
	}

}

func (t *TokenResource) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tokenResponse, err := t.handle(ParseTokenRequest(req))
	if err != nil {
		var tokenErr *TokenError
		if errors.As(err, &tokenErr) {
			tokenErr.RespondJSON(w)
			return
		}
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Add("Content-Type", "application/json")
	// TODO: Check these
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Access-Control-Allow-Methods", "POST")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
	json.NewEncoder(w).Encode(tokenResponse)
}
