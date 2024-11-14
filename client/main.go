package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"deffie-hellman/utils"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
)

type ExchangeRequest struct {
	ClientPublicX string `json:"client_public_x"`
	ClientPublicY string `json:"client_public_y"`
}

type ExchangeResponse struct {
	ServerPublicX string `json:"server_public_x"`
	ServerPublicY string `json:"server_public_y"`
}

type EncryptedRequest struct {
	Data string `json:"data"`
}

func main() {
	// Generate client's ephemeral ECDH keys
	clientPrivateKey, clientPublicKey, err := utils.GenerateECDHKeys()
	if err != nil {
		log.Fatal("Error generating client keys:", err)
	}

	// Send client's public key to server
	reqData := ExchangeRequest{
		ClientPublicX: clientPublicKey.X.String(),
		ClientPublicY: clientPublicKey.Y.String(),
	}
	reqBody, _ := json.Marshal(reqData)
	resp, err := http.Post("http://localhost:8080/exchange", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatal("Error:", err)
	}
	defer resp.Body.Close()

	// Decode server's public key
	var resData ExchangeResponse
	err = json.NewDecoder(resp.Body).Decode(&resData)
	if err != nil {
		log.Fatal("Error decoding response:", err)
	}

	// Convert server's public key
	serverPublicX, _ := new(big.Int).SetString(resData.ServerPublicX, 10)
	serverPublicY, _ := new(big.Int).SetString(resData.ServerPublicY, 10)
	serverPublicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: serverPublicX, Y: serverPublicY}

	// Derive shared secret
	sharedKey, err := utils.DeriveSharedSecret(clientPrivateKey, serverPublicKey)
	if err != nil {
		log.Fatal("Error deriving shared key:", err)
	}
	fmt.Printf("Shared secret (client): %x\n", sharedKey)

	// Encrypt data
	plaintext := "Hello, secure world!"
	encryptedData, err := utils.Encrypt([]byte(plaintext), sharedKey)
	if err != nil {
		log.Fatal("Encryption error:", err)
	}

	// Send encrypted data to server
	secureDataReq := EncryptedRequest{
		Data: encryptedData,
	}
	reqBody, _ = json.Marshal(secureDataReq)
	resp, err = http.Post("http://localhost:8080/secure-data", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatal("Error:", err)
	}
	defer resp.Body.Close()

	fmt.Println("Response from server:", resp.Status)
}
