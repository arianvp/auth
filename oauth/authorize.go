package oauth

type AuthorizationRequest struct {
	GrantType GrantType `json:"grant_type"`
}
