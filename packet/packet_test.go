package packet

import (
	"errors"
	"net"
	"testing"
)

func TestParse(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		_, err := Parse([]byte{})
		if !errors.Is(err, ErrEmptyBytes) {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("ipv6", func(t *testing.T) {
		b := []byte{0}
		_, err := Parse(b)
		if !errors.Is(err, ErrUnsupportedIPv6) {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("happy path", func(t *testing.T) {
		b := newPacket("10.0.0.1", "10.0.0.2")
		p, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		want := net.ParseIP("10.0.0.1")
		got := p.Src
		if !got.Equal(want) {
			t.Fatalf("got: %v want: %v", got, want)
		}
		want = net.ParseIP("10.0.0.2")
		got = p.Dst
		if !got.Equal(want) {
			t.Fatalf("got: %v want: %v", got, want)
		}
	})
}

func newPacket(src, dst string) []byte {
	p := make([]byte, 20)
	p[0] = 0x45 // Version (4) + IHL (5)
	p[9] = 6    // Protocol (TCP)
	s := net.ParseIP(src).To4()
	d := net.ParseIP(dst).To4()
	if s == nil || d == nil {
		panic("invalid IPv4 address")
	}
	copy(p[12:16], s)
	copy(p[16:20], d)
	return p
}
