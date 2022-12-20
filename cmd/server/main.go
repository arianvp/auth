package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"log"
	"net/http"

	"github.com/arianvp/auth/oauth2"
)

func main() {

	origin := flag.String("origin", "", "")

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/oauth2/token", &oauth2.TokenResource{
		PrivateKey:   signer,
		PrivateKeyID: "test",
		Origin:       *origin,
	})
	server := http.Server{
		Handler: mux,
	}

	// TODO: graceful shutdown
	log.Fatal(server.ListenAndServe())
}
