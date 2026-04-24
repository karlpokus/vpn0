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

// Not implemented. Calls Read instead.
func (m *mockIO) ReadFrom(p []byte) (int, net.Addr, error) {
	fakeAddr, err := net.ResolveUDPAddr("udp", "10.200.0.1:8989")
	if err != nil {
		return 0, nil, err
	}
	n, err := m.Read(p)
	return n, fakeAddr, err
}

// Write writes p to WriteC
func (m *mockIO) Write(p []byte) (int, error) {
	m.WriteC <- p
	return len(p), nil
}

// Not implemented. Calls Write instead.
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
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*10)
	// Create mocks and channels.
	//
	// pipeC connects client UDP to server UDP.
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
	}
	serverTUN := &mockIO{
		ReadC:  make(chan []byte),
		WriteC: make(chan []byte),
	}
	// Pass mocks to Client and Server and run them.
	c, err := newClient(clientTUN, clientUDP)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(serverTUN, serverUDP)
	if err != nil {
		t.Fatal(err)
	}
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return c.run(ctx) })
	g.Go(func() error { return s.run(ctx) })
	// Send test packet and make assertions on
	// the entire *upstream route.
	want := newPacket("10.0.0.1", "10.0.0.2")
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
	err = g.Wait()
	if !errors.Is(err, context.Canceled) {
		// Anything but context cancelled
		// is considered a failure
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
