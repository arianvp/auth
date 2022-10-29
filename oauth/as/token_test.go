package as

import (
	"encoding/json"
	"testing"
)

func TestTokenRequest(t *testing.T) {
	var tokenRequest TokenRequest = &AuthorizationCodeGrantTokenRequest{
		ClientAssertionAuthorization: &ClientAssertionAuthorization{
			ClientAssertionType: "lol",
			ClientAssertion:     JWTBearerClientAssertion("yo"),
		},
		Code:         "lol",
		CodeVerifier: "lol",
	}
	serialised, err := json.MarshalIndent(&tokenRequest, "", "  ")
	if err != nil {
		t.Error(err)
	}
	t.Error(string(serialised))
	tokenRequest = &ClientCredentialsGrantTokenRequest{
		ClientAssertionAuthorization: ClientAssertionAuthorization{
			ClientAssertionType: "jwt-bearer",
			ClientAssertion:     JWTBearerClientAssertion("yo"),
		},
	}
	serialised, err = json.MarshalIndent(&tokenRequest, "", "  ")
	if err != nil {
		t.Error(err)
	}
	t.Error(string(serialised))
}
