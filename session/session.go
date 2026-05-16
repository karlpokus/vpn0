package session

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
)

var ErrCounterExhausted = errors.New("counter exhausted")
var ErrZeroPrefix = errors.New("zero prefix")

type Session struct {
	Key     Key
	prefix  [4]byte
	counter uint64
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
func (s *Session) Nonce() ([12]byte, error) {
	if s.counter == math.MaxUint64 {
		return [12]byte{}, ErrCounterExhausted
	}
	if s.prefix == [4]byte{} {
		return [12]byte{}, ErrZeroPrefix
	}
	var nonce [12]byte
	copy(nonce[:4], s.prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], s.counter)
	s.counter++
	return nonce, nil
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
