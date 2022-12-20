package oauth2

// Openid configuration
type ServerConfiguration struct {
	// Issuer is the URL of the OpenID Provider
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint is the URL of the OpenID Provider's OAuth 2.0 Authorization Endpoint
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is the URL of the OpenID Provider's OAuth 2.0 Token Endpoint
	TokenEndpoint string `json:"token_endpoint"`
	// UserInfoEndpoint is the URL of the OpenID Provider's UserInfo Endpoint
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	// JwksURI is the URL of the OpenID Provider's JSON Web Key Set [JWK] document
	JwksURI string `json:"jwks_uri"`
	// RegistrationEndpoint is the URL of the OpenID Provider's Dynamic Client Registration Endpoint
	RegistrationEndpoint string `json:"registration_endpoint"`
	// ScopesSupported is a list of the OAuth 2.0 [RFC6749] scope values that this server supports
	ScopesSupported []string `json:"scopes_supported"`
	// ResponseTypesSupported is a list of the OAuth 2.0 response_type values that this OP supports
	ResponseTypesSupported []string `json:"response_types_supported"`
	// ResponseModesSupported is a list of the OAuth 2.0 response_mode values that this OP supports
	ResponseModesSupported []string `json:"response_modes_supported"`
	// GrantTypesSupported is a list of the OAuth 2.0 Grant Type values that this OP supports
	GrantTypesSupported []string `json:"grant_types_supported"`
	// ACRValuesSupported is a list of the Authentication Context Class References that this OP supports
	ACRValuesSupported []string `json:"acr_values_supported"`
	// SubjectTypesSupported is a list of the Subject Identifier types that this OP supports
	SubjectTypesSupported []string `json:"subject_types_supported"`
	// IDTokenSigningAlgValuesSupported is a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// IDTokenEncryptionAlgValuesSupported is a list of the JWE encryption algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT
}
