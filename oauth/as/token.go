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

type TokenRequest struct {
	ClientAssertionType string `json:"client_assertion_type"`
	ClientAssertion     string `json:"client_assertion"`
	ClientID            string `json:"client_id,omitempty"`
}

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

func (endpoint *TokenEndpoint) createToken(ctx context.Context, r *TokenRequest, webauthnAssertion string) (*TokenResponse, *TokenErrorResponse) {

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
