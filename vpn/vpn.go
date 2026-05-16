package vpn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"vpn0/session"
	"vpn0/tun"
	"vpn0/udp"
)

var ErrUnsupportedMode = errors.New("unsupported mode")

type Config struct {
	Mode         string
	ServerAddr   string
	ServerPubKey string
	KeyPath      string
	IdentityPath string
	TUN          tun.Config
}

// Run starts a vpn client or server depending on selected mode. It is blocking
// and returns once the context expires or an endpoint reader fails, whichever
// comes first.
func Run(ctx context.Context, conf Config) error {
	td, err := tun.New(conf.TUN)
	if err != nil {
		return err
	}
	defer td.Close()
	log.Println("tun device configured")
	b, err := os.ReadFile(conf.KeyPath)
	if err != nil {
		return err
	}
	key, err := privKey(b)
	if err != nil {
		return err
	}
	switch conf.Mode {
	case "client":
		conn, err := udp.NewClient(conf.ServerAddr)
		if err != nil {
			return err
		}
		log.Println("udp client configured")
		pk, err := parsePubKey(conf.ServerPubKey)
		if err != nil {
			return err
		}
		c := &client{
			uc:        conn,
			td:        td,
			key:       key,
			serverKey: pk,
		}
		log.Println("vpn client ready")
		return c.run(ctx)
	case "server":
		conn, err := udp.NewServer(conf.ServerAddr)
		if err != nil {
			return err
		}
		log.Println("udp server configured")
		b, err := os.ReadFile(conf.IdentityPath)
		if err != nil {
			return err
		}
		ids, err := parseIdentities(b)
		if err != nil {
			return err
		}
		log.Printf("got %d pre-approved identities", len(ids))
		s := &server{
			td:  td,
			us:  conn,
			key: key,
			clients: &session.Store{
				Identities: ids,
			},
		}
		log.Println("vpn server ready")
		return s.run(ctx)
	default:
		return fmt.Errorf("%w: *mode", ErrUnsupportedMode)
	}
}

// shutdown closes all items in the list once the context
// is expired.
func shutdown(ctx context.Context, list ...io.Closer) func() error {
	return func() error {
		<-ctx.Done()
		for _, v := range list {
			v.Close()
		}
		return ctx.Err()
	}
}

// parseIdentities parses a list of session.Identity from bytes.
//
// Expected format is net.UDPAddr to private key (base64 encoded)
// separated by whitespace.
func parseIdentities(b []byte) ([]*session.Identity, error) {
	var out []*session.Identity
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		// trim outer whitespace
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			return nil, fmt.Errorf("invalid ip: %q", fields[0])
		}
		addr := &net.UDPAddr{
			IP: ip,
		}
		key, err := parsePubKey(fields[1])
		if err != nil {
			return nil, err
		}
		id := &session.Identity{
			PubKey: key,
			UDP:    addr,
		}
		out = append(out, id)
	}
	return out, scanner.Err()
}
