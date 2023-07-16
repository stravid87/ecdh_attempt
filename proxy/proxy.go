package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

var sharedSecret []byte

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
		ss, err := GenerateSharedSecret(keyPair_backend.PrivateKey.Bytes(), pubk_client_bytes)
		if err != nil {
			fmt.Fprintf(w, "Error calling GenerateSharedSecret()", err.Error())
			return
		}
		sharedSecret = ss
		fmt.Printf("Shared Secret: %v\n", sharedSecret)
	})

	http.HandleFunc("/joke", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("'/joke' api endpoint reached.")

		joke := []byte("This is my joke that is very not random.")

		ciphertext_bytes, err := Encrypt(joke, sharedSecret)
		if err != nil {
			serverError := fmt.Sprintf("Error encrypting: %s", err.Error())
			w.WriteHeader(500)
			w.Write([]byte(serverError))
		}

		ciphertext_hex := hex.EncodeToString(ciphertext_bytes)

		fmt.Println("ciphertext_hex: ", ciphertext_hex)
		w.Write([]byte(ciphertext_hex))
	})

	http.HandleFunc("/receive-joke", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("'/receive-joke' apie endpoint reached.")
		body_Bytes, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Println("Error reading request body ", err.Error())
		}

		ciphertext_bytes, err := hex.DecodeString(string(body_Bytes))
		if err != nil {
			fmt.Println("Error decoding bytes from hex.", err.Error())
		}

		plaintext, err := Decrypt(ciphertext_bytes, sharedSecret)

		fmt.Println("yeah I'm getting it :) ", string(plaintext))

		w.Write(append([]byte("r u getting it?"), body_Bytes...))
	})

	fmt.Println("Listening on localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Failed to ListenAndServer")
	}
}

func GenerateKeyPair(curve ecdh.Curve) (ECDH_KeyPair, error) {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
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
	// if len(key) != 16 || len(key) != 24 || len(key) != 32 {
	// 	return nil, fmt.Errorf("crypto/aes: invalid key size %d, want: 16, 24 or 32", len(key))
	// }

	if len(key) != 32 {
		return nil, fmt.Errorf("crypto/aes: invalid key size %d, wanted: 32", len(key))
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

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("This is the err 1: %w", err)
	}

	nonceSize := gcm.NonceSize()
	fmt.Println("Length of ciphertext passed in: ", len(ciphertext)) // How long is the ciphertext?
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	byteText, err := gcm.Open(nil, nonce, ciphertext, nil)

	return byteText, err
}
