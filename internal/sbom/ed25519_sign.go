package sbom

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

func SignSBOM(doc *SBOMDocument, privateKeyPath string) (string, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	rawKey, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		rawKey = keyData
	}

	if len(rawKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(rawKey))
	}

	privKey := ed25519.PrivateKey(rawKey)

	renderCopy := *doc
	renderCopy.Signature = SignatureResult{}
	renderCopy.Ed25519Signature = ""

	payload, err := json.Marshal(renderCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal SBOM for signing: %w", err)
	}

	sig := ed25519.Sign(privKey, payload)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	return sigB64, nil
}

func SignSBOMData(data []byte, privateKeyPath string) ([]byte, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	rawKey, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		rawKey = keyData
	}

	if len(rawKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(rawKey))
	}

	privKey := ed25519.PrivateKey(rawKey)

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	delete(rawMap, "_ed25519_signature")
	delete(rawMap, "signature")

	payload, err := json.Marshal(rawMap)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal SBOM: %w", err)
	}

	sig := ed25519.Sign(privKey, payload)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	rawMap["_ed25519_signature"] = json.RawMessage(`"` + sigB64 + `"`)

	signed, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed SBOM: %w", err)
	}

	return signed, nil
}

func VerifyEd25519(content []byte, sigB64 string, publicKeyPath string) error {
	keyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	rawKey, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		rawKey = keyData
	}

	if len(rawKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(rawKey))
	}

	pubKey := ed25519.PublicKey(rawKey)

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if !ed25519.Verify(pubKey, content, sig) {
		return fmt.Errorf("signature verification failed: invalid signature")
	}

	return nil
}

func VerifySBOMFile(sbomPath, publicKeyPath string) error {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("failed to read SBOM file: %w", err)
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	sigRaw, ok := rawMap["_ed25519_signature"]
	if !ok {
		return fmt.Errorf("SBOM file does not contain an Ed25519 signature")
	}

	var sigB64 string
	if err := json.Unmarshal(sigRaw, &sigB64); err != nil {
		return fmt.Errorf("failed to parse signature field: %w", err)
	}

	delete(rawMap, "_ed25519_signature")
	delete(rawMap, "signature")

	content, err := json.Marshal(rawMap)
	if err != nil {
		return fmt.Errorf("failed to re-marshal SBOM content: %w", err)
	}

	return VerifyEd25519(content, sigB64, publicKeyPath)
}

func GenerateEd25519KeyPair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	return privB64, pubB64, nil
}
