package main

import (
	"context"
	"flag"
	"log"

	"vpn0/tun"
	"vpn0/vpn"
)

// cli options
var mode = flag.String("m", "client", "VPN mode: client or server")
var tunName = flag.String("tun-name", "vpn0", "TUN device name")
var tunAddr = flag.String("tun-addr", "", "TUN device primary addr")
var tunRoute = flag.String("tun-route", "", "TUN device route")

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tconf := tun.Config{
		Name:  *tunName,
		Addr:  *tunAddr,
		Route: *tunRoute,
	}
	log.Printf("tun conf: %+v", tconf)
	td, err := tun.New(tconf)
	if err != nil {
		log.Println(err)
		return
	}
	defer td.Close()
	log.Printf("tun %s ready", tconf.Name)

	v := vpn.New(*mode)
	// Note! Passing nil here until I support
	// full-duplex copy.
	if err := v.Pipe(ctx, td, nil); err != nil {
		log.Println(err)
	}
}
