package vpn

import (
	"context"
	"errors"
	"io"
	"log"
	"vpn0/packet"
)

var ErrUnsupportedMode = errors.New("unsupported mode")
var ErrModeNotImplemented = errors.New("mode not implemented")

type VPN struct {
	mode string
}

func New(mode string) *VPN {
	return &VPN{mode}
}

// Pipe consults the mode setting and starts piping a to b and
// b to a. Caller owns lifecycle of a and b (Close and related cleanups).
//
// Pipe is blocking.
func (v *VPN) Pipe(ctx context.Context, a, b io.ReadWriter) error {
	switch v.mode {
	case "client":
		return runClientMode(a, b)
	case "server":
		return ErrModeNotImplemented
	default:
		return ErrUnsupportedMode
	}
}

// runClientMode parse-, and copy bytes between a local and remote endpoint.
//
// Note! Only local to remote is implemented for now.
func runClientMode(local, remote io.ReadWriter) error {
	for {
		b := make([]byte, 2048) // MTU x2
		n, err := local.Read(b)
		if err != nil {
			log.Printf("bad read: %v", err)
			continue
		}
		p, err := packet.Parse(b[:n])
		if err != nil {
			log.Printf("bad packet: %v", err)
			continue
		}
		log.Printf("packet: %s", p)
		if packet.IsICMP(p) {
			_, err = local.Write(p.Bytes())
			if err != nil {
				log.Printf("bad local write: %v", err)
			}
			continue
		}
		_, err = remote.Write(p.Bytes())
		if err != nil {
			log.Printf("bad remote write: %v", err)
		}
	}
}
