package session

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

var ErrNotFound = errors.New("not found")

// Store holds a list of identities.
//
// It's concurrency-safe and in-memory only.
type Store struct {
	sync.Mutex
	Identities []*Identity
}

// GetIdentity returns an Identity by addr.
//
// Only UDP.IP is used for comparison.
// UDP.Port is ignored.
func (s *Store) GetIdentity(addr net.Addr) (*Identity, error) {
	s.Lock()
	defer s.Unlock()
	v, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBadAddr, addr)
	}
	for _, id := range s.Identities {
		if id.UDP.IP.Equal(v.IP) {
			return id, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, addr)
}

// GetAddr returns a UDP addr by ip.
func (s *Store) GetAddr(ip net.IP) (*net.UDPAddr, error) {
	s.Lock()
	defer s.Unlock()
	for _, id := range s.Identities {
		if id.TUN.Equal(ip) {
			return id.UDP, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, ip)
}
