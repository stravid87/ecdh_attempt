package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
)

func main() {
	// Declare the plain text you will send
	msg := []byte("Ravi. Are you getting it?")

	// Create a random secret key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatal("io.ReadFull failed to fill key with random bits")
	}

	ciphertext, err := Encrypt(msg, key)
	if err != nil {
		log.Fatal("Faile to encrypt %v", err)
	}

	fmt.Println("msg_encrypted", ciphertext)

	byteText, err := Decrypt(ciphertext, key)

	fmt.Println(string(byteText))

}

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Validate key length
	fmt.Println(len(key))
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
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
