package packet

import (
	"errors"
	"fmt"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var ErrBadICMPType = errors.New("bad ICMP type")

// parseICMP parses b into an ICMP pong Packet.
func parseICMP(b []byte) (*Packet, error) {
	ip, err := ipv4.ParseHeader(b)
	if err != nil {
		return nil, err
	}
	msg, err := icmp.ParseMessage(1, b[ip.Len:])
	if err != nil {
		return nil, err
	}
	if msg.Type != ipv4.ICMPTypeEcho {
		return nil, fmt.Errorf("%w: %v", ErrBadICMPType, msg.Type)
	}
	pong := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: msg.Body,
	}
	// Marshal includes checksum
	icmpBytes, err := pong.Marshal(nil)
	if err != nil {
		return nil, err
	}
	ip.Src, ip.Dst = ip.Dst, ip.Src
	ip.TotalLen = ip.Len + len(icmpBytes)
	ipBytes, err := ip.Marshal()
	if err != nil {
		return nil, err
	}
	p := &Packet{
		proto: ip.Protocol,
		bytes: append(ipBytes, icmpBytes...),
	}
	return p, nil
}

// IsICMP returns true if p is an ICMP packet.
func IsICMP(p *Packet) bool {
	return p.proto == PROTO_ICMP
}
