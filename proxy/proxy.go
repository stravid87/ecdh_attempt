package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

type ECDH_KeyPair struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
}

var keyPair_backend ECDH_KeyPair

func init() {
	ECDH_KeyPair, err := GenerateKeyPair(ecdh.P256())
	if err != nil {
		fmt.Println("Error Generating KeyPair", err.Error())
	}
	keyPair_backend = ECDH_KeyPair
}

func main() {
	// Set up File Server
	fs := http.FileServer(http.Dir("./proxy/static"))
	http.Handle("/", fs)

	http.HandleFunc("/publicKey", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("'/publicKey' api endpoint reached.")
		pk_reader := bytes.NewReader(keyPair_backend.PublicKey.Bytes())
		io.Copy(w, pk_reader)
	})

	http.HandleFunc("/wasmPubk", func(w http.ResponseWriter, r *http.Request) {
		pubk_client_str := r.URL.Query().Get("publicKey")
		pubk_client_str = strings.ReplaceAll(pubk_client_str, "\"", "")
		pubk_client_bytes, err := hex.DecodeString(pubk_client_str)
		if err != nil {
			fmt.Println("Error decoding the pubk_client_str to []bytes: %s", err.Error())
		}
		sharedSecret, err := GenerateSharedSecret(keyPair_backend.PrivateKey.Bytes(), pubk_client_bytes)
		if err != nil {
			fmt.Fprintf(w, "Error @ /pub-key-api", err.Error())
			return
		}
		fmt.Printf("Shared secret: %v", sharedSecret)

	})

	fmt.Println("Listening on localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Failed to ListenAndServer")
	}
}

func GenerateKeyPair(curve ecdh.Curve) (ECDH_KeyPair, error) {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println()
		return ECDH_KeyPair{}, fmt.Errorf("Error calling curve.GenerateKey: %w", err)
	}

	publicKey := privateKey.PublicKey()

	//Note: for ECDH, use the crypto/ecdh package. This function returns an encoding equivalent to that of PublicKey.Bytes in crypto/ecdh.
	return ECDH_KeyPair{PrivateKey: privateKey, PublicKey: publicKey}, nil
}

// GenerateSharedSecret generates a shared secret from own private key and other party's public key.
func GenerateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	z, _ := elliptic.P256().ScalarMult(x, y, privateKey)

	return z.Bytes(), nil
}

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Validate key length
	if len(key) != 16 || len(key) != 24 || len(key) != 32 {
		return nil, fmt.Errorf("crypto/aes: invalid key size %d, want: 16, 24 or 32", len(key))
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}
