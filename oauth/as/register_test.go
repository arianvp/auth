package as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/arianvp/auth/authenticator"
	"github.com/arianvp/webauthn-minimal/webauthn"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/google/uuid"
)

func TestXxx(t *testing.T) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	endpoint := ClientRegistrationEndpoint{
		session:       scs.New(),
		privateKey:    privateKey,
		keyID:         "hey",
		tokenEndpoint: "/token",
		issuer:        "localhost",
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
		Challenge: challenge,
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
	credentialID, attestationObject, err := authn.MakeCredential(clientMetaHash[:], "me.arianvp.myclient")
	if err != nil {
		t.Error(err)
	}

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

	tokenEndpoint := TokenEndpoint{
		session:       scs.New(),
		tokenEndpoint: "/token",
		issuer:        "localhost",
		privateKey:    privateKey,
	}
	ctx, err = endpoint.session.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	endpoint.session.Put(ctx, "challenge", challenge)
	clientData2 := protocol.CollectedClientData{
		Type:      protocol.AssertCeremony,
		Challenge: challenge,
		Origin:    "https://me.arianvp.myclient", // TODO: HACK
	}

	clientDataJSON, err = json.Marshal(clientData2)
	if err != nil {
		t.Fatal(err)
	}

	clientMetaHash = sha256.Sum256(clientDataJSON)

	_, err = authn.GetAssertion(clientMetaHash[:], "me.arianvp.myclient", []webauthn.PublicKeyCredentialDescriptor{{
		Type: "public-key",
		Id:   credentialID,
	}}, false, false)
	if err != nil {
		t.Fatal(err)
	}

	tokenEndpoint.createToken(ctx, &TokenRequest{
		ClientAssertionType: "",
		ClientAssertion:     result.WebauthnAttestationToken,
		ClientID:            result.ClientID,
	}, "")
}
