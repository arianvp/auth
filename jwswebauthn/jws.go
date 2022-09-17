package jwswebauthn

import (
	"crypto/elliptic"
	"math/big"

	"github.com/arianvp/webauthn-minimal/webauthn"
	"github.com/lestrrat-go/jwx/v2/jws"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func WebauthnToJWS(resp *webauthn.AuthenticatorAssertionResponse) *jws.Message {
	msg := jws.NewMessage()

	sig := resp.Signature
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil
	}

	curveBits := elliptic.P256().Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}
	rBytes := r.FillBytes(make([]byte, keyBytes))
	sBytes := s.FillBytes(make([]byte, keyBytes))
	out := append(rBytes, sBytes...)

	msg.AppendSignature(jws.NewSignature().SetSignature(out))

	return msg
}
