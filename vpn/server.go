package vpn

import (
	"context"
	"log"
	"net"
	"sync"
	"vpn0/packet"
	"vpn0/tun"
	"vpn0/udp"

	"golang.org/x/sync/errgroup"
)

type server struct {
	us udp.Server
	td tun.Device
	// clients is an in-mem concurrency-safe mapping
	// of tun IP to public IP, both strings.
	//
	// It's used to lookup client UDP addr by dst IP
	// of return packets.
	clients sync.Map
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
			p, err := packet.Parse(b[:n])
			if err != nil {
				log.Printf("bad packet: %v", err)
				continue
			}
			log.Println(p)
			// save client IPs (no pre-existing check)
			k := p.Src.String()
			v := addr.String()
			log.Printf("[DEBUG] storing %s to %v", k, v)
			s.clients.Store(k, v)
			_, err = s.td.Write(p.Bytes())
			if err != nil {
				log.Printf("bad local write: %v", err)
			}
		}
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
			p, err := packet.Parse(b[:n])
			if err != nil {
				log.Printf("bad packet: %v", err)
				continue
			}
			log.Println(p)
			// lookup client UDP addr by packet dst IP
			k := p.Dst.String()
			v, ok := s.clients.Load(k)
			if !ok {
				log.Printf("bad lookup key: %s", k)
				continue
			}
			addr, err := net.ResolveUDPAddr("udp", v.(string))
			if err != nil {
				log.Printf("bad lookup value: %v", v)
				continue
			}
			_, err = s.us.WriteTo(p.Bytes(), addr)
			if err != nil {
				log.Printf("bad remote write: %v", err)
			}
		}
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

// newServer returns a configured server.
func newServer(td tun.Device, us udp.Server) (*server, error) {
	return &server{
		us: us,
		td: td,
	}, nil
}
