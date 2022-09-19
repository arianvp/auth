package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"log"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
)

func main() {

	// BEGIN SERVER
	attestationRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)

	}
	attestationRootTemplate := &x509.Certificate{
		IsCA: true,
	}
	attestationRoot, err := x509.CreateCertificate(rand.Reader, attestationRootTemplate, attestationRootTemplate, attestationRootKey.Public(), attestationRootKey)
	if err != nil {
		log.Fatal(err)
	}
	attestationRootCert, err := x509.ParseCertificate(attestationRoot)
	if err != nil {
		log.Fatal(err)
	}
	// END SERVER

	// BEGIN CLIENT
	tpm, err := tpm2.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()

	ek, err := client.EndorsementKeyRSA(tpm)
	if err != nil {
		log.Fatal(err)
	}
	defer ek.Close()

	ekCert := ek.Cert()

	ak, err := client.AttestationKeyECC(tpm)
	if err != nil {
		log.Fatal(err)
	}
	defer ak.Close()

	akCSRTemplate := &x509.CertificateRequest{}
	akPrivateKey, err := ak.GetSigner()
	if err != nil {
		log.Fatal(err)
	}
	akCSRBytes, err := x509.CreateCertificateRequest(rand.Reader, akCSRTemplate, akPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	// END CLIENT

	// BEGIN SERVER

	// Check that th EK cert is trusted
	_, err = ekCert.Verify(x509.VerifyOptions{})
	if err != nil {
		log.Fatal(err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}

	// generate a challenge for the the client
	credBlob, encryptedSecret, err := credactivation.Generate(ak.Name().Digest, ek.PublicKey(), 16, secret)
	if err != nil {
		log.Fatal(err)
	}

	// END SERVER

	// BEGIN CLIENT
	decryptedSecret, err := tpm2.ActivateCredential(tpm, ek.Handle(), ak.Handle(), "", "", credBlob, encryptedSecret)
	if err != nil {
		log.Fatal(err)
	}
	// END CLIENT

	// BEGIN SERVER

	// Check if the challenge is solved
	if subtle.ConstantTimeCompare(secret, decryptedSecret) != 0 {
		log.Fatal("Secrets did not match")
	}
	// decode the CSR
	akCSR, err := x509.ParseCertificateRequest(akCSRBytes)
	if err != nil {
		log.Fatal(err)
	}
	if err := akCSR.CheckSignature(); err != nil {
		log.Fatal(err)
	}

	// We know that the AK is backed by the EK and that the EK is trusted at
	// this point! Lets issue a certificate for the AK

	// NOTE: should be populated with the same fields as set on the CSR template In
	// our case it's empty...
	akCertTemplate := &x509.Certificate{}

	akCertBytes, err := x509.CreateCertificate(rand.Reader, akCertTemplate, attestationRootCert, akCSR.PublicKey, attestationRootKey)
	if err != nil {
		log.Fatal(err)
	}
	// END SERVER

	// BEGIN CLIENT
	akCert, err := x509.ParseCertificate(akCertBytes)
	if err != nil {
		log.Fatal(err)
	}
	ak.SetCert(akCert)

	// we can now generate an attestation

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	attestation, err := ak.Attest(client.AttestOpts{
		Nonce: nonce,
	})
	if err != nil {
		log.Fatal(err)
	}
	// END CLIENT

	// BEGIN SERVER
	machineState, err := server.VerifyAttestation(attestation, server.VerifyOpts{
		Nonce:            nonce,
		TrustedRootCerts: []*x509.Certificate{attestationRootCert},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Print(machineState.String())
	// END SERVER
}
