package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

type ECDH_Partner struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
}

//func main() {
	partner1, err := PartnerConstructor(ecdh.P256())
	if err != nil {
		panic("failed to gen partner1")
	}
	partner2, err := PartnerConstructor(ecdh.P256())
	if err != nil {
		panic("faile to gen partner2")
	}

	ssP1, err := partner1.PrivateKey.ECDH(partner2.PublicKey)

	ssP2, err := partner2.PrivateKey.ECDH(partner1.PublicKey)

	fmt.Println(ssP1)
	fmt.Println(ssP2)

}

func PartnerConstructor(curve ecdh.Curve) (ECDH_Partner, error) {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		error := fmt.Errorf("%s", err.Error())
		return ECDH_Partner{}, error
	}

	publicKey := privateKey.PublicKey()

	return ECDH_Partner{privateKey, publicKey}, nil
}
