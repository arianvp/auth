package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/arianvp/auth/authenticator"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/google/uuid"
)

func TestXxx(t *testing.T) {

	endpoint := ClientRegistrationEndpoint{
		session: scs.New(),
	}
	ctx, err := endpoint.session.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}

	aaguid, err := uuid.New().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	authn := authenticator.NewSimpleAuthenticator(aaguid)

	challenge := "123456"
	endpoint.session.Put(ctx, "challenge", challenge)

	clientData := ClientData{
		CollectedClientData: protocol.CollectedClientData{
			Type:      protocol.CreateCeremony,
			Challenge: challenge,
			Origin:    "https://me.arianvp.myclient", // TODO: HACK
		},
		ClientMetadata: ClientMetadata{
			RedirectURIs:            []string{"http://localhost"},
			TokenEndpointAuthMethod: TokenEndpointAuthMethodPrivateKeyWebauthn,
			ClientName:              "Test",
			SoftwareID:              "me.arianvp.myclient",
			SoftwareVersion:         "1.0",
		},
	}

	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatal(err)
	}

	clientMetaHash := sha256.Sum256(clientDataJSON)

	// TODO what should the rpId really be??
	attestationObject, err := authn.MakeCredential(clientMetaHash[:], "me.arianvp.myclient")
	if err != nil {
		t.Error(err)
	}

	// Similar to a JWT. but uses webauthn attestation / assertion for signing
	softwareStatement := base64.RawURLEncoding.EncodeToString(clientDataJSON) + "." + base64.RawURLEncoding.EncodeToString(attestationObject)

	result, rerr := endpoint.register(ctx, &ClientRegistrationRequest{
		SoftwareStatementType: "webauthn-attestation",
		SoftwareStatement:     softwareStatement,
	})
	if rerr != nil {
		t.Fatal(rerr)
	}
	if result.ClientID == "" {
		t.Error("expected a client id")
	}
}
