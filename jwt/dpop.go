package jwt

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
