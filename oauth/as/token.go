package as

import (
	"context"
	"crypto/ecdsa"

	"github.com/alexedwards/scs/v2"
)

type TokenEndpoint struct {
	session       *scs.SessionManager
	tokenEndpoint string
	issuer        string
	privateKey    *ecdsa.PrivateKey
}

type TokenRequest interface {
	Type() string
}

type ClientAuthorization interface {
	ClientID() string
	Authorize() error
}

type ClientAssertion interface {
	Type() string
}

type JWTBearerClientAssertion string

func (JWTBearerClientAssertion) Type() string {
	return "jwt-bearer"
}

type ClientAssertionAuthorization struct {
	ClientAssertionType string          `json:"client_assertion_type"`
	ClientAssertion     ClientAssertion `json:"client_assertion"`
}

type AuthorizationCodeGrantTokenRequest struct {
	*ClientAssertionAuthorization
	ClientID     string `json:"client_id,omitempty"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

// Type implements Grant
func (*AuthorizationCodeGrantTokenRequest) Type() string { return "authorization_code" }

var _ TokenRequest = &AuthorizationCodeGrantTokenRequest{}

type ClientCredentialsGrantTokenRequest struct {
	ClientAssertionAuthorization
}

// Type implements Grant
func (*ClientCredentialsGrantTokenRequest) Type() string { return "client_credentials" }

var _ TokenRequest = &ClientCredentialsGrantTokenRequest{}

type TokenResponse struct {
	IDToken         string `json:"id_token"`
	AccessTokenType string `json:"access_token_type"`
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
}

type TokenErrorResponse struct{}

func (endpoint *TokenEndpoint) fetchClientMetadata(clientID string) *ClientMetadata {
	return nil
}

func (endpoint *TokenEndpoint) createToken(ctx context.Context, r TokenRequest, webauthnAssertion string) (*TokenResponse, *TokenErrorResponse) {

	/*var webauthnAttestationClaims WebauthnAttestationClaims
	if err := jwt.DecodeAndVerify(string(r.ClientAssertion), nil, &webauthnAttestationClaims); err != nil {
		return nil, &TokenErrorResponse{}
	}

	assertionBytes, err := base64.RawURLEncoding.DecodeString(webauthnAssertion)
	if err != nil {
		return nil, &TokenErrorResponse{}
	}

	var assertion protocol.AuthenticatorAssertionResponse

	if err := json.Unmarshal(assertionBytes, &assertion); err != nil {
		return nil, &TokenErrorResponse{}
	}

	if webauthnAttestationClaims.Audience != endpoint.tokenEndpoint {
		return nil, &TokenErrorResponse{}
	}

	if webauthnAttestationClaims.Issuer != endpoint.issuer {
		return nil, &TokenErrorResponse{}
	}

	clientID := webauthnAttestationClaims.Subject

	credential := webauthnAttestationClaims.Confirmation.COSEKeyAsString

	clientMetadata := endpoint.fetchClientMetadata(clientID)

	challenge := endpoint.session.GetString(ctx, "challenge")

	if err := assertion.Verify(challenge, clientMetadata.SoftwareID, "https://"+clientMetadata.SoftwareID, "", false, []byte(credential)); err != nil {
		return nil, &TokenErrorResponse{}
	}

	accessTokenClaims := WebauthnAttestationClaims{
		Issuer:       endpoint.issuer,
		Audience:     "a resource server", // TODO list based on scopes
		Subject:      clientID,
		Confirmation: webauthnAttestationClaims.Confirmation,
	}
	idTokenClaims := WebauthnAttestationClaims{
		Issuer:       endpoint.issuer,
		Audience:     clientID,
		Subject:      clientID,
		Confirmation: webauthnAttestationClaims.Confirmation,
	}

	accessToken, err := jwt.EncodeAndSign(&accessTokenClaims, "keyid", nil)
	if err != nil {
		return nil, &TokenErrorResponse{}
	}

	idToken, err := jwt.EncodeAndSign(&idTokenClaims, "keyid", nil)
	if err != nil {
		return nil, &TokenErrorResponse{}
	}

	return &TokenResponse{
		IDToken:         idToken,
		AccessTokenType: "Webauthn",
		AccessToken:     accessToken,
	}, nil*/
	panic("no")
}
