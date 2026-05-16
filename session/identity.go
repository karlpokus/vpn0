package session

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"net"
)

var ErrBadAddr = errors.New("bad addr")

// An Identity holds networking data and
// session keys.
type Identity struct {
	TUN     net.IP
	UDP     *net.UDPAddr
	PubKey  *ecdh.PublicKey
	Session *Session
}

// SetAddr sets addr on the Identity.
//
// addr is expected to be a *net.UDPAddr
// with both ip and port set.
func (id *Identity) SetAddr(addr net.Addr) error {
	v, ok := addr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("%w: %s", ErrBadAddr, addr)
	}
	id.UDP = v
	return nil
}

// SetIP sets TUN on the Identity.
func (id *Identity) SetIP(ip net.IP) {
	id.TUN = ip
}
