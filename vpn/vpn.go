package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"vpn0/packet"
	"vpn0/tun"
	"vpn0/udp"

	"golang.org/x/sync/errgroup"
)

var ErrUnsupportedMode = errors.New("unsupported mode")

func Run(ctx context.Context, mode string, td tun.Device, UDPServerAddr string) error {
	switch mode {
	case "client":
		conn, err := udp.NewClient(UDPServerAddr)
		if err != nil {
			return err
		}
		log.Printf("UDP connection to %s created", UDPServerAddr)
		defer conn.Close()
		if err := runClient(ctx, td, conn); err != nil {
			return err
		}
	case "server":
		conn, err := udp.NewServer(UDPServerAddr)
		if err != nil {
			return err
		}
		log.Printf("UDP listener on %s created", UDPServerAddr)
		defer conn.Close()
		if err := runServer(ctx, td, conn); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: *mode", ErrUnsupportedMode)
	}
	return nil
}

// runClient runs a vpn client that parse and copy bytes between
// endpoints.
//
// Caller owns endpoint lifecycles (Close and related cleanups).
//
// runClient blocks.
//
// runClient exits after either the context is expired or a failed Read from
// either endpoint.
func runClient(ctx context.Context, td tun.Device, uc udp.Client) error {
	var wg sync.WaitGroup
	// errc is a single channel to report failed Reads from an endpoint.
	//
	// The channel is buffered so no goroutine is blocked from exiting.
	errc := make(chan error, 2)
	// td -> uc
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			b := make([]byte, 2048) // MTU x2
			n, err := td.Read(b)
			if err != nil {
				// fatal
				errc <- err
				return
			}
			p, err := packet.Parse(b[:n])
			if err != nil {
				log.Printf("bad packet: %v", err)
				continue
			}
			log.Println(p)
			if packet.IsICMP(p) {
				_, err = td.Write(p.Bytes())
				if err != nil {
					log.Printf("bad local write: %v", err)
				}
				continue
			}
			_, err = uc.Write(p.Bytes())
			if err != nil {
				log.Printf("bad remote write: %v", err)
			}
		}
	}()
	// uc -> td
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			b := make([]byte, 2048) // MTU x2
			n, err := uc.Read(b)
			if err != nil {
				// fatal
				errc <- err
				return
			}
			p, err := packet.Parse(b[:n])
			if err != nil {
				log.Printf("bad packet: %v", err)
				continue
			}
			log.Println(p)
			_, err = td.Write(p.Bytes())
			if err != nil {
				log.Printf("bad local write: %v", err)
			}
		}
	}()
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errc:
	}
	err = errors.Join(err, td.Close(), uc.Close())
	wg.Wait()
	return err
}

// runServer runs a vpn server that route, parse and copy bytes between
// endpoints.
//
// Caller owns endpoint lifecycles (Close and related cleanups).
//
// runServer blocks.
func runServer(ctx context.Context, td tun.Device, us udp.Server) error {
	// clients is an in-mem concurrency-safe mapping
	// of tunIP to public IP, both strings.
	//
	// It's used to lookup the client UDP addr by dst IP
	// of return packets.
	var clients sync.Map
	// This errgroup is composed of 3 goroutines.
	//
	// It waits on all to return and then returns the first error.
	//
	// If the context expires: the cleanup func will close endpoints which in turn
	// will unblock the readers and have them return.
	//
	// If a reader fails: the goroutine returns the error, which will cancel the context,
	// at which point the cleanup func will run and close the remaining blocking reader and
	// he will return.
	g, ctx := errgroup.WithContext(ctx)
	// cleanup func
	g.Go(func() error {
		<-ctx.Done()
		td.Close()
		us.Close()
		return ctx.Err()
	})
	// us -> td
	g.Go(func() error {
		for {
			b := make([]byte, 2048) // MTU x2
			n, addr, err := us.ReadFrom(b)
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
			clients.Store(k, v)
			_, err = td.Write(p.Bytes())
			if err != nil {
				log.Printf("bad local write: %v", err)
			}
		}
	})
	// td -> us
	g.Go(func() error {
		for {
			b := make([]byte, 2048) // MTU x2
			n, err := td.Read(b)
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
			v, ok := clients.Load(k)
			if !ok {
				log.Printf("bad lookup key: %s", k)
				continue
			}
			addr, err := net.ResolveUDPAddr("udp", v.(string))
			if err != nil {
				log.Printf("bad lookup value: %v", v)
				continue
			}
			_, err = us.WriteTo(p.Bytes(), addr)
			if err != nil {
				log.Printf("bad remote write: %v", err)
			}
		}
	})
	if err := g.Wait(); err != nil {
		return err
	}
	return ctx.Err()
}
