package authenticator

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/arianvp/webauthn-minimal/webauthn"
	"github.com/google/uuid"
)

func Test(t *testing.T) {
	aaguid := uuid.New()

	auth := NewSimpleAuthenticator(aaguid[:])
	clientData := webauthn.ClientData{
		Type:      "webauthn.create",
		Challenge: "0",
		Origin:    "https://google.com",
	}
	clientDataJSON, err := json.Marshal(&clientData)
	if err != nil {
		t.Fatal(err)
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	credentialID, attestationObjectBytes, err := auth.MakeCredential(clientDataHash[:], "google.com")
	if err != nil {
		t.Fatal(err)
	}
	response := webauthn.AuthenticatorAttestationResponse{
		AuthenticatorResponse: webauthn.AuthenticatorResponse{
			ClientDataJSON: clientDataJSON,
		},
		Transports:        []string{},
		AttestationObject: attestationObjectBytes,
	}
	credential, err := response.Verify("0", "google.com", "https://google.com", 0, []webauthn.COSEAlgorithmIdentifier{webauthn.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(credential.ID, credentialID) {
		t.Error("credential ids didn't match")
	}

}
