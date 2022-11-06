package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/arianvp/auth/jwk"
)

func TestJWTWithKeyCnf(t *testing.T) {
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwt := JWT[KeyConfirmation]{
		Issuer:     "https://oidc.arianvp.me",
		Subject:    "https://client.example.com",
		Audience:   []string{"https://google.com"},
		Expiration: time.Time{},
		NotBefore:  time.Time{},
		IssuedAt:   time.Time{},
		JwtID:      "abc",
		Confirmation: KeyConfirmation{
			Key: jwk.EncodePublicKey(subjectKey.PublicKey),
		},
	}
	encoded, err := EncodeAndSign(&jwt, "123", issuerKey)
	if err != nil {
		t.Error(err)
	}
}
