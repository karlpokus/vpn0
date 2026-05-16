package session

import (
	"crypto/ecdh"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

type Key [32]byte

// genKey generates a new session key from an ECDH key exchange and HKDF.
func genKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) (Key, error) {
	ss, err := priv.ECDH(pub)
	if err != nil {
		return Key{}, err
	}
	h := hkdf.New(sha256.New, ss, nil, nil)
	var key Key
	_, err = io.ReadFull(h, key[:])
	return key, err
}
