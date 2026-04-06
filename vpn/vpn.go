package vpn

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"vpn0/packet"
	"vpn0/udp"
)

var ErrUnsupportedMode = errors.New("unsupported mode")

func Run(mode string, rw io.ReadWriter, UDPServerAddr string) error {
	switch mode {
	case "client":
		conn, err := udp.NewClient(UDPServerAddr)
		if err != nil {
			return err
		}
		log.Printf("UDP connection to %s created", UDPServerAddr)
		defer conn.Close()
		if err := runClient(rw, conn); err != nil {
			return err
		}
	case "server":
		conn, err := udp.NewServer(UDPServerAddr)
		if err != nil {
			return err
		}
		log.Printf("UDP listener on %s created", UDPServerAddr)
		defer conn.Close()
		if err := runServer(rw, conn); err != nil {
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
func runClient(rw io.ReadWriter, uc udp.Client) error {
	// rw -> uc
	go func() {
		for {
			b := make([]byte, 2048) // MTU x2
			n, err := rw.Read(b)
			if err != nil {
				log.Printf("bad local read: %v", err)
				continue
			}
			p, err := packet.Parse(b[:n])
			if err != nil {
				log.Printf("bad packet: %v", err)
				continue
			}
			log.Println(p)
			if packet.IsICMP(p) {
				_, err = rw.Write(p.Bytes())
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
	// uc -> rw
	for {
		b := make([]byte, 2048) // MTU x2
		n, err := uc.Read(b)
		if err != nil {
			log.Printf("bad remote read: %v", err)
			continue
		}
		p, err := packet.Parse(b[:n])
		if err != nil {
			log.Printf("bad packet: %v", err)
			continue
		}
		log.Println(p)
		_, err = rw.Write(p.Bytes())
		if err != nil {
			log.Printf("bad local write: %v", err)
		}
	}
}

// runServer runs a vpn server that route, parse and copy bytes between
// endpoints.
//
// Caller owns endpoint lifecycles (Close and related cleanups).
//
// runServer blocks.
func runServer(rw io.ReadWriter, us udp.Server) error {
	// clients is an in-mem concurrency-safe mapping
	// of tunIP to public IP, both strings.
	//
	// It's used to lookup the client UDP addr by dst IP
	// of return packets.
	var clients sync.Map
	// us -> rw
	go func() {
		for {
			b := make([]byte, 2048) // MTU x2
			n, addr, err := us.ReadFrom(b)
			if err != nil {
				log.Printf("bad remote read: %v", err)
				continue
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
			_, err = rw.Write(p.Bytes())
			if err != nil {
				log.Printf("bad local write: %v", err)
			}
		}
	}()
	// rw -> us
	for {
		b := make([]byte, 2048) // MTU x2
		n, err := rw.Read(b)
		if err != nil {
			log.Printf("bad local read: %v", err)
			continue
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
}
