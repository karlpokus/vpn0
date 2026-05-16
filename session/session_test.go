package session

import (
	"errors"
	"math"
	"testing"
)

func TestNonce(t *testing.T) {
	t.Run("ErrZeroPrefix", func(t *testing.T) {
		s := &Session{}
		_, err := s.Nonce()
		if !errors.Is(err, ErrZeroPrefix) {
			t.Fatalf("want %v got %v", ErrZeroPrefix, err)
		}
	})
	t.Run("ErrCounterExhausted", func(t *testing.T) {
		s := &Session{
			counter: math.MaxUint64,
		}
		_, err := s.Nonce()
		if !errors.Is(err, ErrCounterExhausted) {
			t.Fatalf("want %v got %v", ErrCounterExhausted, err)
		}
	})
	t.Run("nonce ok", func(t *testing.T) {
		s := &Session{
			prefix: [4]byte{1, 2, 3, 4},
		}
		nonce, err := s.Nonce()
		if err != nil {
			t.Fatalf("unexpected err:%v", err)
		}
		if nonce == [12]byte{} {
			t.Fatalf("bad nonce: %v", nonce)
		}
	})
}
