package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"syscall/js"
)

type ECDH_KeyPair struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
}

var sharedSecret []byte

func main() {
	c := make(chan struct{})
	js.Global().Set("doECDH", js.FuncOf(doECDH))
	js.Global().Set("getRandomJoke", js.FuncOf(getRandomJoke))
	<-c // block until c pumps something out
}

func doECDH(this js.Value, args []js.Value) interface{} {
	// Async promise functions can be built in the following format
	// 1) Internal functionality
	// 2) get the Promise Constructor
	// 3) call the promiseConstructor
	// 4) return the promise

	var resolve_reject_internals = func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func() {
			// Frontend server generates its keys
			frontendKeyPair, err := GenerateKeyPair(ecdh.P256())
			if err != nil {
				fmt.Println("Error generating frontend keys:", err.Error())
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			// The frontend server sends its public key to the backend server and receives the backend server's public key
			resp, err := http.Get("http://localhost:8080/publicKey")
			if err != nil {
				fmt.Println("Error getting backend public key:", err)
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			// Here, we first check if resp is not nil.
			if resp == nil || resp.Body == nil {
				fmt.Println("Custom Error: resp or resp.Body from ':8080/publicKey' was nil")
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			defer resp.Body.Close()

			// Checking the HTTP status code from ':9091/publicKey'
			if resp.StatusCode != http.StatusOK {
				fmt.Println("Server returned non-OK status: ", resp.Status)
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			backend_pubk, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Error reading backend public key:", err)
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			//The frontend server generates the shared secret
			ss, err := GenerateSharedSecret(frontendKeyPair.PrivateKey.Bytes(), backend_pubk)
			if err != nil {
				fmt.Println("Error generating shared secret:", err)
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}
			//fmt.Println(sharedSecret)
			sharedSecret = ss

			// The frontend server sends its public key to the backend server and receives an encrypted message
			//fmt.Println("http://localhost:8080/wasmPubk?publicKey=" + hex.EncodeToString(frontendKeyPair.PublicKey.Bytes()))
			resp, err = http.Get("http://localhost:8080/wasmPubk?publicKey=" + hex.EncodeToString(frontendKeyPair.PublicKey.Bytes()))
			if err != nil {
				fmt.Println("Error getting message:", err)
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			resolve.Invoke("ECDH a Success")
		}()
		return nil
	}

	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func getRandomJoke(this js.Value, args []js.Value) interface{} {

	var resolve_reject_internals = func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func() {
			// Reach out to the server to get an encrypted random joke
			// Pull from a memory location the shared secret
			// Decrypt the joke
			// Return the plain text to the JS front end
			resp, err := http.Get("http://localhost:8080/joke")
			if err != nil {
				fmt.Println("Error getting :8080/joke: %s", err.Error())
				reject.Invoke(js.ValueOf(err.Error()))
			}
			if resp == nil || resp.Body == nil {
				fmt.Println("Response of response body from http://localhost:8080/joke is nil")
			}

			defer resp.Body.Close()

			responseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Error reading resp.Body:", err.Error())
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			// Checking the HTTP status code
			if resp.StatusCode != http.StatusOK {
				fmt.Println("Server returned non-OK status: ", resp.Status)
				reject.Invoke(js.ValueOf(string(responseBody)))
				return
			}

			ciphertext_bytes, err := hex.DecodeString(string(responseBody))
			if err != nil {
				fmt.Println("Error decoding resp.Body:", err.Error())
				reject.Invoke(js.ValueOf(err.Error()))
			}

			// The frontend server decrypts the message
			plaintext, err := Decrypt(ciphertext_bytes, sharedSecret)
			if err != nil {
				fmt.Println("Error decrypting message:", err)
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			resolve.Invoke(string(plaintext))
		}()
		return nil
	}

	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

// GenerateKeyPair generates a public and private key pair.
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
	fmt.Println(len(key))
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto/aes: invalid key size %d, needed 32", len(key))
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

// Scratch Pad:
// func getEncryptedData(this js.Value, args []js.Value) interface{} {
// 	promiseConstructor := js.Global().Get("Promise")
// 	promise := promiseConstructor.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
// 		resolve := args[0]
// 		reject := args[1]
// 		go func() {

// 			// Frontend server generates its keys
// 			frontendPrivate, frontendPublic, err := GenerateKeyPair()
// 			if err != nil {
// 				fmt.Println("Error generating frontend keys:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			// The frontend server sends its public key to the backend server and receives the backend server's public key
// 			resp, err := http.Get("http://localhost:9091/publicKey")
// 			if err != nil {
// 				fmt.Println("Error getting backend public key:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}
// 			// Here, we first check if resp is not nil.
// 			if resp != nil {
// 				// We also check if resp.Body is not nil before closing it.
// 				if resp.Body != nil {
// 					defer resp.Body.Close()
// 				}
// 				// Checking the HTTP status code
// 				if resp.StatusCode != http.StatusOK {
// 					fmt.Println("Server returned non-OK status: ", resp.Status)
// 				}
// 			}
// oke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			// The frontend server sends its public key to the backend server and receives an encrypted message
// 			resp, err = http.Get("http://localhost:9091/message?publicKey=" + hex.EncodeToString(frontendPublic))
// 			if err != nil {
// 				fmt.Println("Error getting message:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}
// 			// Duplicate the resp and resp.Body null checks for the second http.Get
// 			if resp != nil {
// 				if resp.B
// 			backendPublic, err := ioutil.ReadAll(resp.Body)
// 			if err != nil {
// 				fmt.Println("Error reading backend public key:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			// The frontend server generates the shared secret
// 			sharedSecret, err := GenerateSharedSecret(frontendPrivate, backendPublic)
// 			if err != nil {
// 				fmt.Println("Error generating shared secret:", err)
// 				reject.Invody != nil {
// 					defer resp.Body.Close()
// 				}
// 				// Checking the HTTP status code
// 				if resp.StatusCode != http.StatusOK {
// 					fmt.Println("Server returned non-OK status: ", resp.Status)
// 				}
// 			}

// 			ciphertext, err := ioutil.ReadAll(resp.Body)
// 			if err != nil {
// 				fmt.Println("Error reading message:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}
// 			ciphertextString, _ := hex.DecodeString(string(ciphertext))

// 			// The frontend server decrypts the message
// 			plaintext, err := decrypt(ciphertextString, sharedSecret)
// 			fmt.Println(plaintext)
// 			if err != nil {
// 				fmt.Println("Error decrypting message:", err)
// 				reject.Invoke(js.ValueOf(err.Error()))
// 				return
// 			}

// 			resolve.Invoke(string(plaintext))
// 		}()
// 		return nil
// 	}))

// 	return promise
// }
