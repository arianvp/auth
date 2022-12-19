package main

import (
	"net/http"
)

func main() {
	server := http.Server{
		Addr:    "",
		Handler: nil,
	}
}
