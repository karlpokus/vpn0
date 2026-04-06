package packet

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
)

var ErrEmptyBytes = errors.New("empty bytes")
var ErrUnsupportedIPv6 = errors.New("unsupported IPv6")
var ErrUnsupportedProtocol = errors.New("unsupported protocol")

var PROTO_ICMP int = 1
var PROTO_TCP int = 6

type Packet struct {
	Src   net.IP
	Dst   net.IP
	proto int
	bytes []byte
}

func (p *Packet) Bytes() []byte {
	return p.bytes
}

func (p *Packet) String() string {
	// format: proto src:dst
	if IsICMP(p) {
		return fmt.Sprintf("ICMP %s:%s", p.Src, p.Dst)
	}
	if p.proto == PROTO_TCP {
		return fmt.Sprintf("TCP %s:%s", p.Src, p.Dst)
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
	h, err := ipv4.ParseHeader(b)
	if err != nil {
		return nil, err
	}
	p := &Packet{
		Src: h.Src,
		Dst: h.Dst,
	}
	switch h.Protocol {
	case PROTO_ICMP:
		// TODO: let parseICMP return proto and bytes
		// and we should probably return the ping packet
		// and later create pong on demand.
		return parseICMP(b)
	case PROTO_TCP:
		p.proto = PROTO_TCP
		p.bytes = b
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedProtocol, h.Protocol)
	}
	return p, nil
}
