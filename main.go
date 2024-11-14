package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"deffie-hellman/utils"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
)

var (
	serverPrivateKey *ecdsa.PrivateKey
	serverPublicKey  *ecdsa.PublicKey
	clientPublicKey  *ecdsa.PublicKey
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
	Data string `json:"data"` // Data terenkripsi
}

func init() {
	// Generate server's ECDH key pair
	var err error
	serverPrivateKey, serverPublicKey, err = utils.GenerateECDHKeys()
	if err != nil {
		log.Fatal("Error generating server keys:", err)
	}
}

func keyExchangeHandler(w http.ResponseWriter, r *http.Request) {
	var req ExchangeRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Convert client's public key from string
	clientPublicX, _ := new(big.Int).SetString(req.ClientPublicX, 10)
	clientPublicY, _ := new(big.Int).SetString(req.ClientPublicY, 10)
	clientPublicKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: clientPublicX, Y: clientPublicY}

	// Derive shared secret
	sharedKey, err := utils.DeriveSharedSecret(serverPrivateKey, clientPublicKey)
	if err != nil {
		http.Error(w, "Failed to derive shared secret", http.StatusInternalServerError)
		return
	}
	fmt.Printf("Shared secret (server): %x\n", sharedKey)

	// Send server public key to client
	response := ExchangeResponse{
		ServerPublicX: serverPublicKey.X.String(),
		ServerPublicY: serverPublicKey.Y.String(),
	}
	json.NewEncoder(w).Encode(response)
}

func secureDataHandler(w http.ResponseWriter, r *http.Request) {
	var req EncryptedRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Decrypt data using shared secret
	sharedKey, err := utils.DeriveSharedSecret(serverPrivateKey, clientPublicKey)
	if err != nil {
		http.Error(w, "Failed to derive shared key", http.StatusInternalServerError)
		return
	}
	decryptedData, err := utils.Decrypt(req.Data, sharedKey)
	if err != nil {
		http.Error(w, "Failed to decrypt data", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Decrypted data (server): %s\n", decryptedData)
	w.Write([]byte("Data received and decrypted successfully"))
}

func main() {
	http.HandleFunc("/exchange", keyExchangeHandler)
	http.HandleFunc("/secure-data", secureDataHandler)
	fmt.Println("Server listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
