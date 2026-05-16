package vpn

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

const keySize = 32

var ErrBadKey = errors.New("bad key")

// GenKey returns a new base64 encoded private key.
func GenKey() (string, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()), nil
}

// PubKey returns a public key from the private key bytes.
// Both keys are expected to be base64 encoded.
func PubKey(b []byte) (string, error) {
	k, err := privKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// privKey returns a private key from the base64 encoded
// input bytes.
func privKey(b []byte) (*ecdh.PrivateKey, error) {
	b, err := decodeb64(string(b))
	if err != nil {
		return nil, err
	}
	curve := ecdh.X25519()
	return curve.NewPrivateKey(b)
}

func decodeb64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != keySize {
		return nil, ErrBadKey
	}
	return b, nil
}

func parsePubKey(s string) (*ecdh.PublicKey, error) {
	b, err := decodeb64(s)
	if err != nil {
		return nil, err
	}
	curve := ecdh.X25519()
	return curve.NewPublicKey(b)
}
