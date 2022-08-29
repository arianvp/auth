package main

import (
	"database/sql"
	"flag"
	"log"
	"net/http"
)

var (
	addr     = flag.String("addr", "", "The address on which the server listens")
	certFile = flag.String("cert-file", "", "")
	keyFile  = flag.String("key-file", "", "")
	dsn      = flag.String("dsn", "", "")
)

type Handler struct {
	db *sql.DB
	*http.ServeMux
}

func main() {
	log.Print("db")
	mux := http.NewServeMux()
	db, err := sql.Open("psql", *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	server := http.Server{
		Addr:    *addr,
		Handler: &Handler{db, mux},
	}
	log.Print("Listening on tls")
	log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
}
