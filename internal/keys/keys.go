// Package keys handles local key material:
//
//   - Identity: Ed25519 keypair used to sign ledger entries.
//   - WireGuard: Curve25519 (X25519) keypair used by WireGuard.
//
// These are deliberately separate keypairs (different cryptographic uses
// despite both being Curve25519-family). Both files are stored with mode 0600.
package keys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// Identity is an Ed25519 keypair tied to a node_id.
type Identity struct {
	NodeID     string `json:"node_id"`
	PrivateKey string `json:"private_key"` // base64 of 32-byte seed
	PublicKey  string `json:"public_key"`  // base64 of 32-byte Ed25519 public key
}

// GenerateIdentity creates a fresh Ed25519 identity for node_id.
func GenerateIdentity(nodeID string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{
		NodeID:     nodeID,
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// Sign signs message with the identity's private key.
func (i *Identity) Sign(message []byte) ([]byte, error) {
	seed, err := base64.StdEncoding.DecodeString(i.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private_key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), message), nil
}

// LoadIdentity reads an Identity from a JSON file.
func LoadIdentity(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	if id.NodeID == "" || id.PrivateKey == "" || id.PublicKey == "" {
		return nil, fmt.Errorf("%s: incomplete identity", path)
	}
	return &id, nil
}

// Save writes the Identity to path with mode 0600.
func (i *Identity) Save(path string) error {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// WGKey is a WireGuard X25519 keypair.
type WGKey struct {
	PrivateKey string `json:"private_key"` // base64 of 32-byte clamped private key
	PublicKey  string `json:"public_key"`  // base64 of 32-byte public key
}

// GenerateWGKey creates a fresh WireGuard keypair. The private key is
// already clamped per Curve25519, matching the format `wg genkey` produces.
func GenerateWGKey() (*WGKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &WGKey{
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
		PublicKey:  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// LoadWGKey reads a WGKey from a JSON file.
func LoadWGKey(path string) (*WGKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k WGKey
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	if k.PrivateKey == "" || k.PublicKey == "" {
		return nil, fmt.Errorf("%s: incomplete wg key", path)
	}
	return &k, nil
}

// Save writes the WGKey to path with mode 0600.
func (k *WGKey) Save(path string) error {
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
