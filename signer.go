package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/btcsuite/btcutil/bech32"
	"golang.org/x/crypto/ripemd160"
)

type PrivKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type PubKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ValidatorKey struct {
	Address string  `json:"address"`
	PubKey  PubKey  `json:"pub_key"`
	PrivKey PrivKey `json:"priv_key"`
}

type Message struct {
	Address string `json:"address"`
	NodeID  string `json:"nodeId"`
}

type SignResult struct {
	Address        string `json:"address"`
	PublicKeyB64   string `json:"public_key_b64"`
	SignedMessage  string `json:"signed_message"`
	SignatureHex   string `json:"signature_hex"`
	SignatureValid bool   `json:"signature_valid"`
}

func ripemd160Hash(data []byte) []byte {
	hasher := ripemd160.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func pubkeyToAddress(pubkey []byte) (string, error) {
	sha256Hash := sha256.Sum256(pubkey)
	ripemd160Hash := ripemd160Hash(sha256Hash[:])

	converted, err := bech32.ConvertBits(ripemd160Hash, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits for bech32: %v", err)
	}

	address, err := bech32.Encode("celestiavalcons", converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32 address: %v", err)
	}

	return address, nil
}

func loadPrivateKeyFromFile(filePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var validatorKey ValidatorKey
	if err := json.Unmarshal(data, &validatorKey); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	if validatorKey.PrivKey.Value == "" {
		return nil, fmt.Errorf("private key not found in JSON file")
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(validatorKey.PrivKey.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 private key: %v", err)
	}

	if len(privateKeyBytes) == 64 {
		fmt.Fprintf(os.Stderr, "Debug: Using first 32 bytes of 64-byte key\n")
		privateKeyBytes = privateKeyBytes[:32]
	} else if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 or 64 bytes (base64 decoded), got %d bytes", len(privateKeyBytes))
	}

	return privateKeyBytes, nil
}

func signMessageHex(message Message, privateKeyHex string) (*SignResult, error) {
	if len(privateKeyHex) != 64 {
		return nil, fmt.Errorf("private key must be a 64-character hex string")
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex private key: %v", err)
	}

	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	}

	privateKey := ed25519.PrivateKey(privateKeyBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %v", err)
	}

	signature := ed25519.Sign(privateKey, messageBytes)

	if !ed25519.Verify(publicKey, messageBytes, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	address, err := pubkeyToAddress(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate address: %v", err)
	}

	return &SignResult{
		Address:        address,
		PublicKeyB64:   base64.StdEncoding.EncodeToString(publicKey),
		SignedMessage:  string(messageBytes),
		SignatureHex:   hex.EncodeToString(signature),
		SignatureValid: true,
	}, nil
}

func signMessageB64(message Message, privateKeyB64 string) (*SignResult, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 private key: %v", err)
	}

	if len(privateKeyBytes) == 64 {
		privateKeyBytes = privateKeyBytes[:32]
	} else if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 or 64 bytes (base64 decoded), got %d bytes", len(privateKeyBytes))
	}

	privateKey := ed25519.PrivateKey(privateKeyBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %v", err)
	}

	signature := ed25519.Sign(privateKey, messageBytes)

	if !ed25519.Verify(publicKey, messageBytes, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	address, err := pubkeyToAddress(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate address: %v", err)
	}

	return &SignResult{
		Address:        address,
		PublicKeyB64:   base64.StdEncoding.EncodeToString(publicKey),
		SignedMessage:  string(messageBytes),
		SignatureHex:   hex.EncodeToString(signature),
		SignatureValid: true,
	}, nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <hex_key|file_path> <address> <node_id>\n", os.Args[0])
		os.Exit(1)
	}

	keyInput := os.Args[1]
	address := os.Args[2]
	nodeID := os.Args[3]

	message := Message{
		Address: address,
		NodeID:  nodeID,
	}

	var result *SignResult
	var err error

	if strings.HasSuffix(keyInput, ".json") {
		privateKeyBytes, err := loadPrivateKeyFromFile(keyInput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		privateKeyB64 := base64.StdEncoding.EncodeToString(privateKeyBytes)
		result, err = signMessageB64(message, privateKeyB64)
	} else {
		result, err = signMessageHex(message, keyInput)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Address: %s\n", result.Address)
	fmt.Printf("Message: %s\n", result.SignedMessage)
	fmt.Printf("Signature: %s\n", result.SignatureHex)
	if result.SignatureValid {
		fmt.Println("Signature valid")
	} else {
		fmt.Println("Invalid signature")
	}
}
