package vpn

import (
	"context"
	"crypto/ecdh"
	"log"
	"net"
	"vpn0/packet"
	"vpn0/session"
	"vpn0/tun"
	"vpn0/udp"

	"golang.org/x/sync/errgroup"
)

type server struct {
	us  udp.Server
	td  tun.Device
	key *ecdh.PrivateKey
	// A list of pre-approved identities
	clients *session.Store
}

// upstream forwards packets upstream.
func (s *server) upstream(ctx context.Context) func() error {
	return func() error {
		for {
			b := make([]byte, 2048) // MTU x2
			n, addr, err := s.us.ReadFrom(b)
			if err != nil {
				// graceful shutdown
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			go s.upstreamHandler(b[:n], addr)
		}
	}
}

func (s *server) upstreamHandler(b []byte, addr net.Addr) {
	id, err := s.clients.GetIdentity(addr)
	if err != nil {
		log.Println(err)
		return
	}
	err = id.SetAddr(addr)
	if err != nil {
		log.Println(err)
		return
	}
	if !id.Session.Established() {
		sess, err := session.New(s.key, id.PubKey)
		if err != nil {
			log.Println(err)
			return
		}
		id.Session = sess
	}
	b, err = packet.Decrypt(id.Session.Key, b)
	if err != nil {
		log.Println(err)
		return
	}
	p, err := packet.Parse(b)
	if err != nil {
		log.Printf("bad packet: %v", err)
		return
	}
	log.Println(p)
	id.SetIP(p.Src)
	_, err = s.td.Write(p.Bytes())
	if err != nil {
		log.Printf("bad local write: %v", err)
	}
}

// downstream forwards packets downstream.
func (s *server) downstream(ctx context.Context) func() error {
	return func() error {
		for {
			b := make([]byte, 2048) // MTU x2
			n, err := s.td.Read(b)
			if err != nil {
				// graceful shutdown
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			go s.downstreamHandler(b[:n])
		}
	}
}

func (s *server) downstreamHandler(b []byte) {
	p, err := packet.Parse(b)
	if err != nil {
		log.Printf("bad packet: %v", err)
		return
	}
	log.Println(p)
	// lookup client UDP addr by packet dst IP
	addr, err := s.clients.GetAddr(p.Dst)
	if err != nil {
		log.Println(err)
		return
	}
	id, err := s.clients.GetIdentity(addr)
	if err != nil {
		log.Println(err)
		return
	}
	if !id.Session.Established() {
		sess, err := session.New(s.key, id.PubKey)
		if err != nil {
			log.Println(err)
			return
		}
		id.Session = sess
	}
	nonce, err := id.Session.Nonce()
	if err != nil {
		log.Println(err)
		return
	}
	ct, err := packet.Encrypt(id.Session.Key, nonce, p.Bytes())
	if err != nil {
		log.Println(err)
		return
	}
	_, err = s.us.WriteTo(ct, addr)
	if err != nil {
		log.Printf("bad remote write: %v", err)
	}
}

// run starts a blocking vpn server. It exits on context
// expired or a failed read on any endpoint, whichever comes first.
func (s *server) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(shutdown(ctx, s.td, s.us))
	g.Go(s.upstream(ctx))
	g.Go(s.downstream(ctx))
	if err := g.Wait(); err != nil {
		return err
	}
	return ctx.Err()
}
