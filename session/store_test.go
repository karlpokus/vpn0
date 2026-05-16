package session

import (
	"net"
	"testing"
)

func TestStore(t *testing.T) {
	tunIP := net.ParseIP("10.100.3.1")
	pubIP := net.ParseIP("10.100.1.231")
	want := &Identity{
		TUN: tunIP,
		UDP: &net.UDPAddr{
			IP: pubIP,
			// ignore port
		},
	}
	st := &Store{
		Identities: []*Identity{want},
	}
	t.Run("GetIdentity", func(t *testing.T) {
		addr := &net.UDPAddr{
			IP:   pubIP,
			Port: 8989,
		}
		got, err := st.GetIdentity(addr)
		if err != nil {
			t.Fatal(err)
		}
		if !equal(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})
	t.Run("GetAddr", func(t *testing.T) {
		addr, err := st.GetAddr(tunIP)
		if err != nil {
			t.Fatal(err)
		}
		if addr.String() != want.UDP.String() {
			t.Fatalf("got %s want %s", addr, want.UDP)
		}
	})
}

func equal(a, b *Identity) bool {
	if a == nil && b == nil {
		return true
	}
	if !a.TUN.Equal(b.TUN) {
		return false
	}
	if a.UDP.String() != b.UDP.String() {
		return false
	}
	return true
}
