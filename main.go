package main

/*

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// BEGIN SERVER
	attestationRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)

	}
	attestationRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	attestationRoot, err := x509.CreateCertificate(rand.Reader, attestationRootTemplate, attestationRootTemplate, attestationRootKey.Public(), attestationRootKey)
	if err != nil {
		log.Fatal(err)
	}
	attestationRootCert, err := x509.ParseCertificate(attestationRoot)
	if err != nil {
		log.Fatal(err)
	}
	rootCertPool := x509.NewCertPool()
	rootCertPool.AddCert(attestationRootCert)

	// END SERVER

	// BEGIN CLIENT
	if os.Getenv("CLOUD_SHELL") == "true" {
		cmd := exec.Command("sudo", "chmod", "777", "/dev/tpmrm0")
		if b, err := cmd.CombinedOutput(); err != nil {
			log.Fatal(string(b))
		}
	}

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

	ak, err := client.AttestationKeyRSA(tpm)
	if err != nil {
		log.Fatal(err)
	}
	defer ak.Close()
	// END CLIENT

	// BEGIN SERVER

	if ekCert != nil {
		_, err = ekCert.Verify(x509.VerifyOptions{})
		if err != nil {
			log.Fatal(err)
		}
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
	decryptedSecret, err := ak.ActivateCredential(tpm, ek, credBlob, encryptedSecret)
	if err != nil {
		log.Fatal(err)
	}
	// END CLIENT

	// BEGIN SERVER

	// Check if the challenge is solved
	if subtle.ConstantTimeCompare(secret, decryptedSecret) != 1 {
		log.Fatal("Secrets did not match")
	}

	// We know that the AK is backed by the EK and that the EK is trusted at
	// this point! Lets issue a certificate for the AK

	// NOTE: should be populated with the same fields as set on the CSR template In
	// our case it's empty...
	akCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	akCertBytes, err := x509.CreateCertificate(rand.Reader, akCertTemplate, attestationRootCert, ak.PublicKey(), attestationRootKey)
	if err != nil {
		log.Fatal(err)
	}
	// END SERVER

	// BEGIN CLIENT
	akCert, err := x509.ParseCertificate(akCertBytes)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := akCert.Verify(x509.VerifyOptions{
		Roots:     rootCertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
	}); err != nil {
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
*/
