package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
)

type PublicKeyHandler struct {
	curveP256 ecdh.Curve
	privateK  *ecdh.PrivateKey
	publicK   *ecdh.PublicKey
}

func (pkh PublicKeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "private: %v, public: %v", pkh.privateK, pkh.publicK)
}

func main() {
	// Set up File Server
	fs := http.FileServer(http.Dir("./proxy/static"))
	http.Handle("/", fs)

	// Set up the public key handler
	theCurve := ecdh.P256()
	privateKey, err := theCurve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error Generating private key", err.Error())
	}
	http.Handle("/publicKey", PublicKeyHandler{theCurve, privateKey, privateKey.PublicKey()})

	fmt.Println("Listening on localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Failed to ListenAndServer")
	}

}
