package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/arianvp/auth/jwk"
)

type header struct {
	// The algorithm used for signature.
	Algorithm string `json:"alg"`
	// Represents the token type.
	Typ string `json:"typ"`
	// The hint which key is being used.  ID Tokens SHOULD NOT use the JWS or
	// JWE x5u, x5c, jku, or jwk Header Parameter fields. Instead, references to
	// keys used are communicated in advance using Discovery and Registration
	// parameters, per Section 10.
	KeyID string   `json:"kid,omitempty"`
	Key   *jwk.Key `json:"jwk,omitempty"`
}

type StringList []string

func (l *StringList) UnmarshalJSON(data []byte) error {
	var s string
	var as []string
	serr := json.Unmarshal(data, &s)
	aerr := json.Unmarshal(data, &as)
	if serr == nil {
		*l = []string{s}
	} else if aerr == nil {
		*l = as
	} else if serr != nil {
		return serr
	} else if aerr != nil {
		return aerr
	}
	return nil
}

type KeyReference struct {
	KeyID  string `json:"kid"`           // https://www.rfc-editor.org/rfc/rfc7800.html
	KeyURL string `json:"jku,omitempty"` // https://www.rfc-editor.org/rfc/rfc7800.html

}
type Confirmer[T any] interface {
	Confirm(*T) error
}

// Confirmation describes how the presenter of the JWT posesses a particular
// proof-of-ossession key and how the recipient can cryptographically confirm
// proof of possession of the key by the presenter.
type KeyIDConfirmation struct {
	KeyReference
}

type KeyConfirmation struct {
	Key *jwk.Key `json:"jwk"` // https://www.rfc-editor.org/rfc/rfc7800.html
}

type KeyThumbprintConfirmation struct {
	KeyThumbprint []byte `json:"jkt"` // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop
}

type dPoPConfirmer struct {
}

// Confirm implements Confirmer
func (*dPoPConfirmer) Confirm(key *KeyThumbprintConfirmation) error {
	panic("unimplemented")
}

func NewDPoPConfirmer() Confirmer[KeyThumbprintConfirmation] {
	return &dPoPConfirmer{}
}

type CertificateThumbprintConfirmation struct {
	CertificateThumbprint []byte `json:"x5t#S256"` // https://www.rfc-editor.org/rfc/rfc8705#name-jwt-certificate-thumbprint-
}

type certificateThumbprintConfirmer struct {
	peer *x509.Certificate // If set, Peer is used for confirmation
}

func NewCertificateThumbprintConfirmerFromRequest(req *http.Request) (Confirmer[CertificateThumbprintConfirmation], error) {
	if req.TLS == nil {
		return nil, fmt.Errorf("http request was not performed with TLS")
	}
	return NewCertificateThumbprintConfirmerFromTLS(req.TLS)
}

func NewCertificateThumbprintConfirmerFromTLS(tls *tls.ConnectionState) (Confirmer[CertificateThumbprintConfirmation], error) {
	if len(tls.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate")
	}
	return NewCertificateThumbprintConfirmer(tls.PeerCertificates[0]), nil
}

func NewCertificateThumbprintConfirmer(peer *x509.Certificate) Confirmer[CertificateThumbprintConfirmation] {
	return &certificateThumbprintConfirmer{peer}
}

// Confirm implements Confirmer
func (confirmer *certificateThumbprintConfirmer) Confirm(cnf *CertificateThumbprintConfirmation) error {
	x5t := sha256.Sum256(confirmer.peer.Raw)
	if !bytes.Equal(cnf.CertificateThumbprint, x5t[:]) {
		return fmt.Errorf("cnf: certificate thumbprints did not match")
	}
	return nil
}

type Validator[T any] interface {
	Validate(*T) error
}

type JWTValidator[T any] struct {
	Issuer               string
	Subject              string
	Audience             string
	CheckJwtIDRevocation func(jti string) error
	Now                  func() time.Time
	Confirmer            Confirmer[T]
}

var _ Validator[JWT[any]] = &JWTValidator[any]{}

func (v *JWTValidator[T]) Validate(t *JWT[T]) error {
	if v.Issuer != t.Issuer {
		return fmt.Errorf("unexpected issuer: %s", t.Issuer)
	}
	if v.Subject != t.Subject {
		return fmt.Errorf("unexpected sub: %s", t.Subject)
	}
	found := false
	for _, aud := range t.Audience {
		if aud == v.Audience {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("aud %s not present", v.Audience)
	}

	if v.CheckJwtIDRevocation != nil {
		if err := v.CheckJwtIDRevocation(t.JwtID); err != nil {
			return err
		}
	}
	if v.Confirmer != nil {
		if err := v.Confirmer.Confirm(&t.Confirmation); err != nil {
			return err
		}
	}

	var now time.Time
	if v.Now == nil {
		now = time.Now()
	} else {
		now = v.Now()
	}

	if now.Before(t.IssuedAt) {
		return fmt.Errorf("now is before iat: %v", t.IssuedAt)
	}
	if now.Before(t.NotBefore) {
		return fmt.Errorf("now is before nbf: %v", t.NotBefore)
	}
	if now.After(t.Expiration) {
		return fmt.Errorf("now is after exp: %v", t.Expiration)
	}
	return nil
}

var _ JWTValidator[CertificateThumbprintConfirmation] = JWTValidator[CertificateThumbprintConfirmation]{
	Confirmer: NewCertificateThumbprintConfirmer(nil),
}

type JWT[Confirmation any] struct {
	Issuer       string       `json:"iss,omitempty"`
	Subject      string       `json:"sub,omitempty"`
	Audience     StringList   `json:"aud,omitempty"`
	Expiration   time.Time    `json:"exp,omitempty"`
	NotBefore    time.Time    `json:"nbf,omitempty"`
	IssuedAt     time.Time    `json:"iat,omitempty"`
	JwtID        string       `json:"jti,omitempty"`
	Confirmation Confirmation `json:"cnf,omitempty"`
}

func (token *JWT[Confirmation]) Type() string { return "JWT" }

// AccessToken defines the  JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
// See https://datatracker.ietf.org/doc/html/rfc9068
type AccessToken[Confirmation any] struct {
	JWT[Confirmation]
	ClientID                            string     `json:"client_id"`
	AuthTime                            *time.Time `json:"auth_time,omitempty"`
	AuthenticationContextClassReference string     `json:"acr,omitempty"`
	AuthenticationMethodsReference      string     `json:"amr,omitempty"`
	Scope                               string     `json:"scope,omitempty"`

	Roles        []string `json:"roles,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
}

var _ Token[any] = &AccessToken[any]{}

func (token *AccessToken[Confirmation]) Type() string { return "at+jwt" }

// AccessTokenValidator validates a JWT according to https://datatracker.ietf.org/doc/html/rfc9068#section-4
type AccessTokenValidator[Confirmation any] struct {
	JWTValidator[Confirmation]
}

func (v *AccessTokenValidator[Cnf]) Validate(t *AccessToken[Cnf]) error {
	if t.Subject == "" {
		return fmt.Errorf("sub is required")
	}
	if t.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if err := v.JWTValidator.Validate(&t.JWT); err != nil {
		return err
	}
	return nil
}

type Token[T any] interface {
	Type() string
}

func EncodeAndSign(claims Token[any], keyID string, privateKey *ecdsa.PrivateKey) (string, error) {

	header := header{
		Algorithm: "ES256",
		Typ:       claims.Type(),
		KeyID:     keyID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	toSign := strings.Join([]string{headerB64, claimsB64}, ".")
	hash := sha256.Sum256([]byte(toSign))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}
	curveBits := privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	signature := append(rBytesPadded, sBytesPadded...)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return strings.Join([]string{headerB64, claimsB64, signatureB64}, "."), nil

}

func DecodeAndVerify(jwt string, getPublicKey func(keyID string) (*ecdsa.PublicKey, error), claims Token[any]) error {
	parts := strings.Split(jwt, ".")
	if len(parts) < 3 {
		return errors.New("jwt: invalid token received")
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var h2 header
	if err := json.Unmarshal(h, &h2); err != nil {
		return err
	}
	if h2.Typ != claims.Type() {
		return fmt.Errorf("jws: Unexpected type: %s", h2.Typ)
	}
	if h2.Algorithm != "ES256" {
		return fmt.Errorf("jws: Unsupported algorithm: %s", h2.Algorithm)
	}
	publicKey, err := getPublicKey(h2.KeyID)
	if err != nil {
		return err
	}
	c, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	toSign := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(toSign))
	curveBits := publicKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}
	r := big.NewInt(0).SetBytes(signature[:keyBytes])
	s := big.NewInt(0).SetBytes(signature[keyBytes:])
	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return fmt.Errorf("jwt: invalid signature")
	}
	if err := json.Unmarshal(c, claims); err != nil {
		return err
	}
	return nil
}
