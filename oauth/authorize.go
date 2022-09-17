package oauth

type ResponseType string

const (
	ResponseTypeCode ResponseType = "code"
)

type CodeChallengeMethod string

const (
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

// A Code is a JWT signed AND encerypted by the authorization server.
// A code JWT is identifier by "jti" member.
// A code JWT is single use.
type CodeClaims struct {
	ClientId            string `json:"client_id"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	RedirectUri         string `json:"redirect_uri"`
	UniqueId            string `json:"jti"`
	IssuedAt            string `json:"iat"`
	NotBefore           string `json:"nbf"`
	NotAfter            string `json:"exp"`
}

type SignedAuthorizationRequest struct {
	ResponseType        ResponseType        `json:"response_type"`
	ClientId            string              `json:"client_id"`
	RedirectUri         string              `json:"redirect_uri"`
	State               string              `json:"state"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method"`
	CodeChallenge       string              `json:"code_challenge"`
}

// POST'd by the client (back-channel)
type PushedAuthorizationRequest struct {
	// A App-Attest assertion containing a SignedAuthorizationRequest
	Request  string `json:"request"`
	ClientId string `json:"client_id"`
}

type PushedAuthorizationResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// GET'd by the resource owner (front-channel).
type AuthorizationRequest struct {
	ClientId   string `json:"client_id"`
	RequestUri string `json:"request_uri"`
}

type AuthorizationResponse struct {
	Code   string `json:"code"`
	State  string `json:"state"`
	Issuer string `json:"iss"`
}
