package vpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
	"vpn0/session"

	"golang.org/x/sync/errgroup"
)

// mockIO implements tun.Device
// and udp.{Client, Server}
//
// Blocking IO is simulated
// by channels.
type mockIO struct {
	ReadC  chan []byte
	WriteC chan []byte
	Addr   *net.UDPAddr
}

// Read copies reads from ReadC to p.
func (m *mockIO) Read(p []byte) (int, error) {
	b, ok := <-m.ReadC
	if !ok {
		return 0, io.EOF // net.ErrClosed
	}
	if len(b) == 0 {
		return 0, fmt.Errorf("0 bytes on ReadC")
	}
	// drop remainder
	n := copy(p, b)
	return n, nil
}

// Not implemented. Calls Read with a static addr.
func (m *mockIO) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := m.Read(p)
	return n, m.Addr, err
}

// Write writes p to WriteC
func (m *mockIO) Write(p []byte) (int, error) {
	m.WriteC <- p
	return len(p), nil
}

// Not implemented. Calls Write instead and ignores addr.
func (m *mockIO) WriteTo(b []byte, _ net.Addr) (int, error) {
	return m.Write(b)
}

// Close closes blocking reader
func (m *mockIO) Close() error {
	close(m.ReadC)
	return nil
}

// Test_upstream asserts that packets put on ClientTUN
// are routed to serverTUN.
//
// TODO: test roundtrip
func Test_upstream(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
	// Create mocks
	//
	// pipeC connects client UDP to server UDP.
	//
	// clientUDPAddr is used in session.Identity and
	// serverUDP mock.
	clientUDPAddr := &net.UDPAddr{
		IP: net.ParseIP("10.100.1.231"),
	}
	pipeC := make(chan []byte)
	clientTUN := &mockIO{
		ReadC:  make(chan []byte),
		WriteC: make(chan []byte),
	}
	clientUDP := &mockIO{
		ReadC:  make(chan []byte),
		WriteC: pipeC,
	}
	serverUDP := &mockIO{
		ReadC:  pipeC,
		WriteC: make(chan []byte),
		Addr:   clientUDPAddr,
	}
	serverTUN := &mockIO{
		ReadC:  make(chan []byte),
		WriteC: make(chan []byte),
	}
	// create keys
	clientKey, err := privKey([]byte("wzTFMQqEk0Ss8BWC/vugD1tYhcuukUMSxkYEI31PvVM="))
	if err != nil {
		t.Fatal(err)
	}
	clientPubKey, err := parsePubKey("bXVAuthrWKrum1W/PpgvwZipKqPkkbDacZ7mQguAFR0=")
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := privKey([]byte("ih64kDQhyIlogzyVHPTmS1b3cxhxyAad2buCGoS3xvI="))
	if err != nil {
		t.Fatal(err)
	}
	serverPubKey, err := parsePubKey("6EDDHi+d5i7OkATe76f1qfg9dxMND3TFKgHh4dpr+Vg=")
	if err != nil {
		t.Fatal(err)
	}
	// Pass mocks and keys to Client and Server and run them.
	c := &client{
		uc:        clientUDP,
		td:        clientTUN,
		key:       clientKey,
		serverKey: serverPubKey,
	}
	s := &server{
		us:  serverUDP,
		td:  serverTUN,
		key: serverKey,
		clients: &session.Store{
			Identities: []*session.Identity{
				{
					PubKey: clientPubKey,
					UDP:    clientUDPAddr,
				},
			},
		},
	}
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return c.run(ctx) })
	g.Go(func() error { return s.run(ctx) })
	go func() {
		// Send test packet and make assertions on
		// the entire *upstream route.
		want := newPacket("10.100.3.1", "10.100.2.178")
		clientTUN.ReadC <- want
		got := <-serverTUN.WriteC
		if !bytes.Equal(want, got) {
			t.Errorf("got %v want %v", got, want)
		}
		// Assertions are done and all endpoints are back at reader blocking state.
		//
		// Now we cancel the context and expect that error be returned from errgroup.
		//
		// Cancelling the context will close all endpoints (unblocking readers)
		// before returning.
		cancel()
	}()
	err = g.Wait()
	// Anything but context.Canceled is considered a failure,
	// including context.DeadlineExceeded.
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
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

func Test_parseIdentities(t *testing.T) {
	b := []byte(`
	10.100.1.231 JL4VXLrwe57F6fZYw/nM5JXNsXnNgXpWuvIDh08gKGc=
	`)
	ids, err := parseIdentities(b)
	if err != nil {
		t.Fatal(err)
	}
	want := net.ParseIP("10.100.1.231")
	got := ids[0].UDP.IP
	if !got.Equal(want) {
		t.Fatalf("got %s want %s", got, want)
	}
}
