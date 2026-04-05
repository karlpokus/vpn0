package packet

import (
	"errors"
	"fmt"

	"golang.org/x/net/ipv4"
)

var ErrEmptyBytes = errors.New("empty bytes")
var ErrUnsupportedIPv6 = errors.New("unsupported IPv6")
var ErrUnsupportedProtocol = errors.New("unsupported protocol")

var PROTO_ICMP int = 1
var PROTO_TCP int = 6

type Packet struct {
	proto int
	bytes []byte
}

func (p *Packet) Bytes() []byte {
	return p.bytes
}

func (p *Packet) String() string {
	if IsICMP(p) {
		return "ICMP"
	}
	if p.proto == PROTO_TCP {
		return "TCP"
	}
	return "unknown protocol"
}

// Parse parses b into a Packet and returns it.
//
// Unsupported protocols return ErrUnsupportedProtocol.
func Parse(b []byte) (*Packet, error) {
	if len(b) == 0 {
		return nil, ErrEmptyBytes
	}
	// skip ipv6
	if b[0]>>4 != 4 {
		return nil, ErrUnsupportedIPv6
	}
	ip, err := ipv4.ParseHeader(b)
	if err != nil {
		return nil, err
	}
	switch ip.Protocol {
	case PROTO_ICMP:
		return parseICMP(b)
	case PROTO_TCP:
		return &Packet{
			proto: PROTO_TCP,
			bytes: b,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedProtocol, ip.Protocol)
	}
}
