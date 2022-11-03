package as

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/arianvp/auth/jwt"
	"github.com/arianvp/webauthn-minimal/webauthn"
	"github.com/google/uuid"
)

type TokenEndpointAuthMethod string

const (
	TokenEndpointAuthMethodPrivateKeyWebauthn      TokenEndpointAuthMethod = "private_key_webauthn"
	TokenEndpointAuthMethodSelfSignedTlsClientAuth TokenEndpointAuthMethod = "self_signed_tls_client_auth"
	TokenEndpointAuthMethodNone                    TokenEndpointAuthMethod = "none"
)

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
)

type ResponseType string

const (
	ResponseTypeCode ResponseType = "code"
)

type ClientMetadata struct {
	RedirectURIs            []string                `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod TokenEndpointAuthMethod `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []GrantType             `json:"grant_types,omitempty"`
	ResponseTypes           []ResponseType          `json:"response_types,omitempty"`
	ClientName              string                  `json:"client_name,omitempty"`
	ClientURI               string                  `json:"client_uri,omitempty"`
	LogoURI                 string                  `json:"logo_uri,omitempty"`
	Scope                   string                  `json:"scope,omitempty"`
	Contacts                []string                `json:"contacts,omitempty"`
	TOSURI                  string                  `json:"tos_uri,omitempty"`
	PolicyURI               string                  `json:"policy_uri,omitempty"`
	JWKSURI                 string                  `json:"jwks_uri,omitempty"`
	JWKS                    string                  `json:"jwks,omitempty"`
	SoftwareID              string                  `json:"software_id,omitempty"`
	SoftwareVersion         string                  `json:"software_version,omitempty"`
}

type SoftwareStatementType string

// TODO: Formalize these names
const (
	SoftwareStatementTypeJWT                 SoftwareStatementType = "jwt"
	SoftwareStatementTypeWebauthnAttestation SoftwareStatementType = "webauthn-attestation"
)

// A valid ClientDataJSON according to the Webauthn spec, that also contains ClientMetadata
type ClientData struct {
	Challenge string `json:"challenge"`
	// If the attestation object has information about the client metadata it MUST validate this against the user-provided metadata.
	ClientMetadata ClientMetadata `json:"client_metadata"`
}

type Base64URLString string

// Corresponds to an AuthenticatorAttestationResponse from Webauthn https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse
type AuthenticatorAttestationResponse struct {
	ClientDataJSON    Base64URLString `json:"clientDataJSON"`    // Base64url-encoded json-encoded ClientMetadata
	AttestationObject Base64URLString `json:"attestationObject"` // base64url-encoded AttestationObject
}
type ClientRegistrationRequest struct {
	ClientMetadata // Unsigned client metadata MAY be provided.  Client metadata in the software statement MUST always have priority.

	// Defaults to "jwt" when omitted
	SoftwareStatementType SoftwareStatementType `json:"software_statement_type,omitempty"`
	// Signed Client Metadata and potentially a corresponding attestation object (when type is "webauthn")
	// Claims in the SoftwareStatement override any claims outside of it.
	SoftwareStatement string `json:"software_statement,omitempty"`
}

// https://www.rfc-editor.org/rfc/rfc8747.html#name-confirmation-claim
// but with an additional possibility to have a COSE Key inside
type WebauthnConfirmation struct {
	// COSE_Key as per https://www.rfc-editor.org/rfc/rfc8747.html
	// COSEKey *webauthn.PublicKeyData `json:"-" cbor:"1,keyasint,omitempty"`

	// a COSE_Key encoded as a bytestring
	COSEKeyAsString Base64URLString `json:"cwk,omitempty" cbor:"-"`

	// A reference to a credential.  client should have saved the corresponding credential id
	CredentialId string `json:"kid,omitempty"`
}

type ClientInformationResponse struct {
	ClientID string `json:"client_id"`

	// A Holder-of-Key assertion (RFC7521) binding the credential id to the client id
	// MUST be signed by a key from jwks_uri
	// It's provided as a client_assertion for protected endpoints.  a DPoP header must
	// be set containing a Webauthn Assertion that proofs possession of the keys
	WebauthnPOPToken string `json:"webauthn_pop_token"`

	// The Client metadata. This is either client-provided or populated from the
	// attestation statement if possible.  For example. Apple's AppAttest
	// attestion statement will contain the AppID which corresponds to the
	// Software ID.  but it will not contain the redirect_uris of your app.  If
	// the client provided values do not match the attestation statement the
	// response MUST fail with an `invalid_client_metadata`
	ClientMetadata
}

type ClientRegistrationError string

const (
	ClientRegistrationErrorInvalidRedirectURI          ClientRegistrationError = "invalid_redirect_uri"
	ClientRegistrationErrorInvalidClientMetadata       ClientRegistrationError = "invalid_client_metadata"
	ClientRegistrationErrorInvalidSoftwareStatement    ClientRegistrationError = "invalid_software_statement"
	ClientRegistrationErrorUnapprovedSoftwareStatement ClientRegistrationError = "unapproved_software_statement"
)

func (e *ClientRegistrationError) Error() string {
	return string(*e)
}

type ClientRegistrationErrorResponse struct {
	ErrorCode        ClientRegistrationError `json:"error"`
	ErrorDescription string                  `json:"error_description"`
}

func (e *ClientRegistrationErrorResponse) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode.Error(), e.ErrorDescription)
}

type ClientRegistrationEndpoint struct {
	session       *scs.SessionManager
	issuer        string
	tokenEndpoint string

	keyID      string
	privateKey *ecdsa.PrivateKey
}

// Registers a Relying Party to the Authorisation Server.
// The Relying Party provides a software_id that is common accross all instances of the Relying Party.
// After proving cryptographically that the Relying Party is indeed an instance of the software (through means of attestation).
// a client_id is minted to uniquely identiy the Relying Party and it's associated with the software_id.
// The attestation can optionally contain Authenticator Data indicating what hardware bound key is used
// later for Proof of Possesion style authentication. Not all Relying Parties support this.
// TODO:
// 1. Prove that the software_id is 'owned' by the registering client through means of attestation
// 2. Associate the software_id to the client_id so we can verify later assertions as the signatures
// will include the RPID
func (endpoint *ClientRegistrationEndpoint) register(ctx context.Context, r *ClientRegistrationRequest) (*ClientInformationResponse, *ClientRegistrationErrorResponse) {

	clientID := uuid.NewString()

	switch r.TokenEndpointAuthMethod {
	case TokenEndpointAuthMethodNone:
		return &ClientInformationResponse{
			ClientID:         clientID,
			WebauthnPOPToken: "",
			ClientMetadata:   r.ClientMetadata}, nil
	case TokenEndpointAuthMethodPrivateKeyWebauthn:
		privateKeyWebauthn(endpoint, ctx, r)

	case TokenEndpointAuthMethodSelfSignedTlsClientAuth:
	}

	return nil, nil

}

func privateKeyWebauthn(endpoint *ClientRegistrationEndpoint, ctx context.Context, r *ClientRegistrationRequest) (any, error) {

	// if the request is empty, we see this as a sign that we need to issue an save a challenge
	if r.SoftwareStatement == "" {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: "software statement is required",
		}
	}

	// TODO default to JWT

	if r.SoftwareStatementType != SoftwareStatementTypeWebauthnAttestation {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: fmt.Sprintf("only %s is supported", SoftwareStatementTypeWebauthnAttestation),
		}
	}

	parts := strings.Split(r.SoftwareStatement, ".")
	if len(parts) != 2 {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: "Not right format",
		}
	}
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	var clientData ClientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	challenge := endpoint.session.GetString(ctx, "challenge")
	if clientData.Challenge != challenge {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: "challenge mismatch",
		}
	}

	attestationObjectBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	// TODO attestation should check challeng!
	attestationObject, err := webauthn.ParseAndVerifyAttestationObject(attestationObjectBytes)
	if err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	authData, err := webauthn.ParseAndVerifyAuthenticatorData(bytes.NewReader(attestationObject.AuthenticatorData), clientData.ClientMetadata.SoftwareID, 0)
	// TODO: Check that software_id is among a known software id
	if err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	iat := time.Now()

	jti := uuid.NewString()

	webauthnClaims := &jwt.JWT[jwt.WebauthnConfirmation]{
		Issuer:       endpoint.issuer,
		Subject:      clientID,
		Audience:     []string{endpoint.tokenEndpoint},
		Expiration:   time.Time{},
		NotBefore:    iat,
		IssuedAt:     iat,
		JwtID:        jti,
		Confirmation: jwt.WebauthnConfirmation{},
	}

	popToken, err := jwt.EncodeAndSign(webauthnClaims, endpoint.keyID, endpoint.privateKey)
	if err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorUnapprovedSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}
	return nil, nil
}

func (endpoint *ClientRegistrationEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Add("Content-Type", "application/json")

	// Unconditionally set a challenge and save it. A client that doesn't have a
	// challenge yet should send an empty request, expect a bad_request, and
	// create a software_statement with the nonce next time
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)
	endpoint.session.Put(r.Context(), "challenge", challenge)
	w.Header().Set("Webauthn-Nonce", challenge)

	encoder := json.NewEncoder(w)
	var clientRegistrationRequest ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&clientRegistrationRequest); err != nil {
		encoder.Encode(&ClientRegistrationErrorResponse{
			ErrorCode:        "invalid_request",
			ErrorDescription: err.Error(),
		})
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	resp, rerr := endpoint.register(r.Context(), &clientRegistrationRequest)
	if rerr != nil {
		w.WriteHeader(http.StatusBadRequest)
		encoder.Encode(rerr)
		return
	}
	w.WriteHeader(http.StatusCreated)
	encoder.Encode(resp)
}
