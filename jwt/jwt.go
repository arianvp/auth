package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type Confirmation struct {
	KeyID string `json:"kid"`
}

func (c *Confirmation) ConfirmJWS(jws string) error {
	return nil
}

type Token interface {
	Type() string
}

func EncodeAndSign(t Token, privateKeyId string, privateKey crypto.Signer) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "P-256", "typ": t.Type(), "kid": privateKeyId})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	toSign := append(append(header, '.'), claims...)
	digest := sha256.Sum256(toSign)
	signature, err := privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	return string(append(append(toSign, '.'), signatureB64...)), nil
}
