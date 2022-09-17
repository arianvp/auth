package main

import (
	"log"

	"github.com/arianvp/auth/attestationca"
	"github.com/google/go-attestation/attest"
)

func main() {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		log.Fatal(err)
	}
	eks, err := tpm.EKs()
	if err != nil {
		log.Fatal(err)
	}
	ek := eks[0]

	ak, err := tpm.NewAK(nil)
	if err != nil {
		log.Fatal(err)
	}
	enroller := attestationca.Enroller{}

	encryptedCredential, err := enroller.StartActivation(&ek, ak.AttestationParameters(), tpm.Version())
	if err != nil {
		log.Fatal(err)
	}

	secret, err := ak.ActivateCredential(tpm, *encryptedCredential)
	if err != nil {
		log.Fatal(err)
	}
	cert := enroller.FinishActivation(secret)

	key, err := tpm.NewKey(ak, &attest.KeyConfig{
		Algorithm:      "",
		Size:           0,
		QualifyingData: []byte{},
	})
}
