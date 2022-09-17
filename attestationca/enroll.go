package attestationca

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/go-attestation/attest"
)

type Enroller struct {
	client *http.Client
	secret []byte
	signer crypto.Signer
	rootCA *x509.Certificate
}

func (enroller *Enroller) StartActivation(ek *attest.EK, ak attest.AttestationParameters, tpmVersion attest.TPMVersion) (*attest.EncryptedCredential, error) {
	trustedTpmRoots := x509.NewCertPool()
	certificate := ek.Certificate
	if certificate == nil && ek.CertificateURL != "" {
		response, err := enroller.client.Get(ek.CertificateURL)
		if err != nil {
			return nil, err
		}
		certBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		certificate, err = attest.ParseEKCertificate(certBytes)
		if err != nil {
			return nil, err
		}
	}
	if certificate == nil {
		return nil, fmt.Errorf("No certificate for EK found. Can not continue")
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	// TODO check if publicKey is equal to ek.Public
	_, err := certificate.Verify(x509.VerifyOptions{
		Roots:         trustedTpmRoots,
		Intermediates: certPool,
	})
	if err != nil {
		return nil, err
	}
	// TODO check transparency log
	activation := attest.ActivationParameters{
		TPMVersion: tpmVersion,
		EK:         ek.Public,
		AK:         ak,
	}
	secret, challenge, err := activation.Generate()

	enroller.secret = secret
	// TODO Store secret in session
	return challenge, err
}

// TODO how to integrate with ACME?
// Returns a signed certificate for AK
func (enroller *Enroller) FinishActivation(version attest.TPMVersion, ak attest.AttestationParameters, receivedSecret []byte) ([]byte, error) {
	if subtle.ConstantTimeCompare(enroller.secret, receivedSecret) != 1 {
		return nil, fmt.Errorf("secret didn't match")
	}

	akPublic, err := attest.ParseAKPublic(version, ak.Public)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{}
	signedCert, err := x509.CreateCertificate(rand.Reader, template, enroller.rootCA, akPublic.Public, enroller.signer)
	if err != nil {
		return nil, err
	}
	return signedCert, nil
}
