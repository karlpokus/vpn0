package session

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestEncryption(t *testing.T) {
	t.Run("ErrShortBytes", func(t *testing.T) {
		s := new(Session)
		pt := []byte{}
		_, err := s.Encrypt(pt)
		if !errors.Is(err, ErrShortBytes) {
			t.Fatalf("want %v got %v", ErrShortBytes, err)
		}
	})
	t.Run("ErrMissingKey", func(t *testing.T) {
		s := new(Session)
		pt := []byte("secret message")
		_, err := s.Encrypt(pt)
		if !errors.Is(err, ErrMissingKey) {
			t.Fatalf("want %v got %v", ErrMissingKey, err)
		}
	})
	t.Run("ErrCounterExhausted", func(t *testing.T) {
		s := &Session{}
		copy(s.Key[:], "12345678901234567890123456789012")
		s.counter.Add(math.MaxUint64)
		pt := []byte("secret message")
		_, err := s.Encrypt(pt)
		if !errors.Is(err, ErrCounterExhausted) {
			t.Fatalf("want %v got %v", ErrCounterExhausted, err)
		}
	})
	t.Run("ErrZeroPrefix", func(t *testing.T) {
		s := &Session{}
		copy(s.Key[:], "12345678901234567890123456789012")
		pt := []byte("secret message")
		_, err := s.Encrypt(pt)
		if !errors.Is(err, ErrZeroPrefix) {
			t.Fatalf("want %v got %v", ErrZeroPrefix, err)
		}
	})
	t.Run("happy path", func(t *testing.T) {
		s := &Session{}
		copy(s.Key[:], "12345678901234567890123456789012")
		s.prefix = [4]byte{'a', 'b', 'c', 'd'}
		msg := []byte("secret message")
		ct, err := s.Encrypt(msg)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		pt, err := s.Decrypt(ct)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("got %v want %v", pt, msg)
		}
	})
}
