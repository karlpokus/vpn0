package packet

import (
	"bytes"
	"testing"
	"vpn0/session"
)

func TestDecrypt(t *testing.T) {
	var key session.Key
	copy(key[:], "12345678901234567890123456789012")
	var nonce [12]byte
	copy(key[:], "123456789012")
	msg := []byte("secret message")
	ct, err := Encrypt(key, nonce, msg)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("got %v want %v", pt, msg)
	}
}
