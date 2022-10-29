package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
)

type EC2PublicKey struct {
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

type Key struct {
	KeyID   string `json:"kid,omitempty"`
	KeyType string `json:"kty"`
	Use     string `json:"use,omitempty"`
	EC2PublicKey
}

func encodeCoord(keyBytes int, b *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(b.FillBytes(make([]byte, keyBytes)))
}

func decodeCoord(s string) (*big.Int, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return big.NewInt(0).SetBytes(xBytes), nil
}

func curveByName(curveName string) (elliptic.Curve, error) {
	switch curveName {
	case elliptic.P224().Params().Name:
		return elliptic.P224(), nil
	case elliptic.P256().Params().Name:
		return elliptic.P256(), nil
	case elliptic.P384().Params().Name:
		return elliptic.P384(), nil
	case elliptic.P521().Params().Name:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unknown curveName: %s", curveName)
	}
}

func EncodePublicKey(keyID string, pubKey ecdsa.PublicKey) Key {

	curveBits := pubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	return Key{
		KeyID:   keyID,
		KeyType: "EC",
		Use:     "sig",
		EC2PublicKey: EC2PublicKey{
			Curve: pubKey.Params().Name,
			X:     encodeCoord(keyBytes, pubKey.X),
			Y:     encodeCoord(keyBytes, pubKey.Y),
		},
	}
}

func (jwk *Key) GetPublicKey() (ecdsa.PublicKey, error) {
	curve, err := curveByName(jwk.Curve)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	x, err := decodeCoord(jwk.X)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	y, err := decodeCoord(jwk.Y)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	publicKey := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}
