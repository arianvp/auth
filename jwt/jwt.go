package jwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

type JWK ecdsa.PublicKey

func (jwk *JWK) Thumbprint() (string, error) {
	bytes, err := jwk.MarshalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil

}

func (jwk *JWK) MarshalJSON() ([]byte, error) {
	return json.Marshal(jwkk{
		Curve: "P-256",
		X:     base64.RawURLEncoding.EncodeToString(jwk.X.Bytes()),
		Y:     base64.RawURLEncoding.EncodeToString(jwk.Y.Bytes()),
		Kty:   "EC",
	})
}

type jwkk struct {
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
	Kty   string `json:"kty"`
}

func (jwk *JWK) UnmarshalJSON(data []byte) error {
	var k jwkk
	if err := json.Unmarshal(data, &k); err != nil {
		return err
	}
	if k.Curve != "P-256" {
		ErrUnsupportedCurve := errors.New("unsupported curve: " + k.Curve)
		return ErrUnsupportedCurve
	}
	if k.Kty != "EC" {
		ErrUnsupportedKeyType := errors.New("unsupported key type: " + k.Kty)
		return ErrUnsupportedKeyType
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return err
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return err
	}
	*jwk = JWK{X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	return nil
}

type Confirmation struct {
	JWK JWK `json:"jwk,omitempty"`
}

func (c *Confirmation) ConfirmJWS(jws string) error {
	return nil
}

type Token struct {
	Issuer       string       `json:"iss"`
	Subject      string       `json:"sub"`
	Audience     []string     `json:"aud"`
	JWTID        string       `json:"jti"`
	Expiration   int64        `json:"exp"`
	IssuedAt     int64        `json:"iat"`
	AuthTime     int64        `json:"auth_time,omitempty"`
	ACR          string       `json:"acr,omitempty"`
	AMR          []string     `json:"amr,omitempty"`
	Confirmation Confirmation `json:"cnf"`
}

// an ID Token is a JWT with a set of predefined claims (see
// http://openid.net/specs/openid-connect-core-1_0.html#IDToken)
type IDToken struct {
	Token
}

func (t *IDToken) Type() string {
	return "jwt+id_token"
}

type AccessToken struct {
	Token
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

func (t *AccessToken) Type() string {
	return "jwt+at"
}
