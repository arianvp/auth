package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"
	"github.com/arianvp/auth/jwt"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncbor"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
)

type TokenEndpointAuthMethod string

const (
	TokenEndpointAuthMethodPrivateKeyWebauthn TokenEndpointAuthMethod = "private_key_webauthn"
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
	// Unused when using webauthn. So Ignore
	// JWKSURI                 string                  `json:"jwks_uri,omitempty"`
	// JWKS                    string                  `json:"jwks,omitempty"`
	SoftwareID      string `json:"software_id,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`
}

type SoftwareStatementType string

// TODO: Formalize these names
const (
	// SoftwareStatementTypeJWT                 SoftwareStatementType = "jwt"
	SoftwareStatementTypeWebauthnAttestation SoftwareStatementType = "webauthn-attestation"
)

// A valid ClientDataJSON according to the Webauthn spec, that also contains ClientMetadata
type ClientData struct {
	protocol.CollectedClientData
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
	*ClientMetadata // Unsigned client metadata MAY be provided.  Client metadata in the software statement MUST always have priority.

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
	COSEKey *webauthncose.EC2PublicKeyData `json:"-" cbor:"1,keyasint,omitempty"`

	// a COSE_Key encoded as a bytestring
	COSEKeyAsString Base64URLString `json:"ck,omitempty" cbor"-"`

	// A reference to a credential.  client should have saved the corresponding credential id
	CredentialId Base64URLString `json:"kid,omitempty",cbor:"3,keyasint,omitempty"`
}

// https://www.rfc-editor.org/rfc/rfc8747.html#section-3
type WebauthnAttestationClaims struct {
	Issuer       string               `json:"iss"` // MUST be equal to issuer id in the metadata endpoint
	Audience     string               `json:"aud"` // MUST be equal to token_endpoint metadata endpoint
	Subject      string               `json:"sub"` // MUST be equal to the client_id
	Confirmation WebauthnConfirmation `json:"cnf"`
}

type ClientInformationResponse struct {
	ClientID string `json:"client_id"`

	// A Holder-of-Key assertion (RFC7521) binding the credential id to the client id
	// MUST be signed by a key from jwks_uri
	WebauthnAttestationToken string `json:"webauthn_attestation_token"`

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

func (endpoint *ClientRegistrationEndpoint) register(ctx context.Context, r *ClientRegistrationRequest) (*ClientInformationResponse, *ClientRegistrationErrorResponse) {
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

	// HACK: nasty trick to make it match the RpId
	if err := clientData.Verify(challenge, protocol.CreateCeremony, "https://"+clientData.ClientMetadata.SoftwareID); err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	attestationObjectBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	var attestationObject protocol.AttestationObject
	if err := webauthncbor.Unmarshal(attestationObjectBytes, &attestationObject); err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorInvalidSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	// TODO: Check that software_id is among a known software id

	// HACK: This is just to trick webauthn library in handling attestations without UP
	attestationObject.AuthData.Flags |= protocol.FlagUserPresent
	// Ideally apple should allow you to configure the relying party id to be
	// the server you send the attestation to. It doesn't do that;
	// unfortunately.  This means attestation is currently vulnerable to
	// rebinding attacks if an attacker can Man in the Middle the client.

	clientDataHash := sha256.Sum256(clientDataJSON)
	if err := attestationObject.Verify(clientData.ClientMetadata.SoftwareID, clientDataHash[:], false); err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorUnapprovedSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	clientID := uuid.NewString()

	webauthnClaims := &WebauthnAttestationClaims{
		Issuer:       endpoint.issuer,
		Audience:     endpoint.tokenEndpoint,
		Subject:      clientID,
		Confirmation: WebauthnConfirmation{},
	}

	webauthnAttestationToken, err := jwt.EncodeAndSign(webauthnClaims, endpoint.keyID, endpoint.privateKey)
	if err != nil {
		return nil, &ClientRegistrationErrorResponse{
			ErrorCode:        ClientRegistrationErrorUnapprovedSoftwareStatement,
			ErrorDescription: err.Error(),
		}
	}

	return &ClientInformationResponse{
		ClientID:                 clientID,
		ClientMetadata:           clientData.ClientMetadata,
		WebauthnAttestationToken: webauthnAttestationToken,
	}, nil

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
