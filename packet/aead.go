package packet

import (
	"errors"
	"vpn0/session"

	"golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = chacha20poly1305.NonceSize

var ErrShortPacket = errors.New("short packet")

func Encrypt(key session.Key, nonce [12]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	out := aead.Seal(nil, nonce[:], plaintext, nil)
	return append(nonce[:], out...), nil
}

func Decrypt(key session.Key, data []byte) ([]byte, error) {
	if len(data) < NonceSize {
		return nil, ErrShortPacket
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := data[:NonceSize]
	ct := data[NonceSize:]
	return aead.Open(nil, nonce, ct, nil)
}
