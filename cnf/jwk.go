package cnf
}

type KeyReference struct {
	KeyID  string `json:"kid"`           // https://www.rfc-editor.org/rfc/rfc7800.html
	KeyURL string `json:"jku,omitempty"` // https://www.rfc-editor.org/rfc/rfc7800.html

}

// Confirmation describes how the presenter of the JWT posesses a particular
// proof-of-ossession key and how the recipient can cryptographically confirm
// proof of possession of the key by the presenter.
type KeyReferenceConfirmation struct {
	KeyReference
}

type keyReferenceConfirmer struct {
}

// Confirm implements Confirmer
func (*keyReferenceConfirmer) Confirm(cnf *KeyReferenceConfirmation) error {
	panic("unimplemented")
}

var _ Confirmer[KeyReferenceConfirmation] = &keyReferenceConfirmer{}

type KeyConfirmation struct {
	Key jwk.Key `json:"jwk"` // https://www.rfc-editor.org/rfc/rfc7800.html
}

type keyConfirmer struct {
	jws string
}

// Confirm implements Confirmer
func (*keyConfirmer) Confirm(cnf *KeyConfirmation) error {
	return nil
}

var _ Confirmer[KeyConfirmation] = &keyConfirmer{}