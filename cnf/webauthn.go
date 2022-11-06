package cnf

type WebauthnConfirmation struct{}
type webauthnConfirmer struct{}

// Confirm implements Confirmer
func (*webauthnConfirmer) Confirm(cnf *WebauthnConfirmation) error {
	panic("unimplemented")
}

var _ Confirmer[WebauthnConfirmation] = &webauthnConfirmer{}
