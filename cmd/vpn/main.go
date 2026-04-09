package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"vpn0/tun"
	"vpn0/vpn"
)

// cli options
var mode = flag.String("m", "client", "VPN mode: client or server")
var tunName = flag.String("tun-name", "vpn0", "TUN device name")
var tunAddr = flag.String("tun-addr", "", "TUN device primary addr")
var tunRoute = flag.String("tun-route", "", "TUN device route")
var UDPServerAddr = flag.String("udp-server-addr", "", "UDP server addr: host:port")

func main() {
	flag.Parse()
	log.Printf("mode: %s", *mode)

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := vpn.Run(ctx, *mode, td, *UDPServerAddr); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	log.Println("vpn exited")
}
