package vpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"vpn0/tun"
	"vpn0/udp"
)

var ErrUnsupportedMode = errors.New("unsupported mode")

type Config struct {
	Mode       string
	ServerAddr string
	TUN        tun.Config
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

	switch conf.Mode {
	case "client":
		conn, err := udp.NewClient(conf.ServerAddr)
		if err != nil {
			return err
		}
		c, err := newClient(td, conn)
		if err != nil {
			return err
		}
		return c.run(ctx)
	case "server":
		conn, err := udp.NewServer(conf.ServerAddr)
		if err != nil {
			return err
		}
		s, err := newServer(td, conn)
		if err != nil {
			return err
		}
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
