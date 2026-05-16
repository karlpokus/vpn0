package vpn

import (
	"context"
	"crypto/ecdh"
	"log"
	"vpn0/packet"
	"vpn0/session"
	"vpn0/tun"
	"vpn0/udp"

	"golang.org/x/sync/errgroup"
)

type client struct {
	uc        udp.Client
	td        tun.Device
	key       *ecdh.PrivateKey
	serverKey *ecdh.PublicKey
	session   *session.Session
}

// upstream forwards packets upstream.
func (c *client) upstream(ctx context.Context) func() error {
	return func() error {
		for {
			b := make([]byte, 2048) // MTU x2
			n, err := c.td.Read(b)
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
			if packet.IsICMP(p) {
				_, err = c.td.Write(p.Bytes())
				if err != nil {
					log.Printf("bad local write: %v", err)
				}
				continue
			}
			if !c.session.Established() {
				s, err := session.New(c.key, c.serverKey)
				if err != nil {
					return err
				}
				c.session = s
			}
			nonce, err := c.session.Nonce()
			if err != nil {
				return err
			}
			ct, err := packet.Encrypt(c.session.Key, nonce, p.Bytes())
			if err != nil {
				return err
			}
			_, err = c.uc.Write(ct)
			if err != nil {
				log.Printf("bad remote write: %v", err)
			}
		}
	}
}

// downstream forwards packets downstream.
func (c *client) downstream(ctx context.Context) func() error {
	return func() error {
		for {
			b := make([]byte, 2048) // MTU x2
			n, err := c.uc.Read(b)
			if err != nil {
				// graceful shutdown
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			if !c.session.Established() {
				s, err := session.New(c.key, c.serverKey)
				if err != nil {
					return err
				}
				c.session = s
			}
			b, err = packet.Decrypt(c.session.Key, b[:n])
			if err != nil {
				return err
			}
			p, err := packet.Parse(b)
			if err != nil {
				log.Printf("bad packet: %v", err)
				continue
			}
			log.Println(p)
			_, err = c.td.Write(p.Bytes())
			if err != nil {
				log.Printf("bad local write: %v", err)
			}
		}
	}
}

// run starts a blocking vpn client. It exits on context
// expired or a failed read on any endpoint, whichever comes first.
func (c *client) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(shutdown(ctx, c.td, c.uc))
	g.Go(c.upstream(ctx))
	g.Go(c.downstream(ctx))
	if err := g.Wait(); err != nil {
		return err
	}
	return ctx.Err()
}
