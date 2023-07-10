// package main

// import (
// 	"crypto/ecdh"
// 	"fmt"
// 	"net/http"
// )

// type PublicKeyHandler struct {
// 	curveP256 ecdh.Curve
// 	privateK  ecdh.PrivateKey
// 	publicK   ecdh.PublicKey
// }

// func (pkh PublicKeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	fmt.Fprintf(w, "%s", "Hello from the PublicKeyHandler")
// }
