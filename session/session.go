package session

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = chacha20poly1305.NonceSize

var ErrCounterExhausted = errors.New("counter exhausted")
var ErrZeroPrefix = errors.New("zero prefix")
var ErrShortBytes = errors.New("short bytes")
var ErrMissingKey = errors.New("missing key")

type Session struct {
	// TODO: make private
	Key Key
	// TODO: add dedicated nonce data structure
	prefix  [4]byte
	counter atomic.Uint64
}

// Established returns true if the Session is established and ready to use.
// It's always safe to call, even on a nil Session.
//
// Note! Established should be consulted before using
// New(), Nonce() and Key.
func (s *Session) Established() bool {
	if s == nil {
		return false
	}
	return s.Key != Key{}
}

// Nonce returns a 12 byte nonce and a non-nil error if any
// pre-requisites are missing.
//
// TODO: make private
func (s *Session) Nonce() ([12]byte, error) {
	n := s.counter.Add(1)
	if n == 0 {
		return [12]byte{}, ErrCounterExhausted
	}
	if s.prefix == [4]byte{} {
		return [12]byte{}, ErrZeroPrefix
	}
	var nonce [12]byte
	copy(nonce[:4], s.prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce, nil
}

// Encrypt encrypts the provided plaintext.
func (s *Session) Encrypt(pt []byte) ([]byte, error) {
	if len(pt) == 0 {
		return nil, ErrShortBytes
	}
	if !s.Established() {
		return nil, ErrMissingKey
	}
	aead, err := chacha20poly1305.New(s.Key[:])
	if err != nil {
		return nil, err
	}
	nonce, err := s.Nonce()
	if err != nil {
		return nil, err
	}
	out := aead.Seal(nil, nonce[:], pt, nil)
	return append(nonce[:], out...), nil
}

// Decrypt decrypts the data frame payload in b.
func (s *Session) Decrypt(b []byte) ([]byte, error) {
	if !s.Established() {
		return nil, ErrMissingKey
	}
	if len(b) < NonceSize {
		return nil, ErrShortBytes
	}
	aead, err := chacha20poly1305.New(s.Key[:])
	if err != nil {
		return nil, err
	}
	nonce := b[:NonceSize]
	ct := b[NonceSize:]
	return aead.Open(nil, nonce, ct, nil)
}

// New returns an established Session ready to use.
func New(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) (*Session, error) {
	key, err := genKey(priv, pub)
	if err != nil {
		return nil, err
	}
	s := &Session{
		Key: key,
	}
	if _, err := rand.Read(s.prefix[:]); err != nil {
		return nil, err
	}
	return s, nil
}
