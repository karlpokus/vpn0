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
var serverAddr = flag.String("server-addr", "", "Server addr: host:port")
var serverPubKey = flag.String("server-pubkey", "", "Server public key")
var keyPath = flag.String("key-path", "", "Filepath to private key")
var identityPath = flag.String("id-path", "", "Filepath to pre-approved identities")

func main() {
	flag.Parse()
	conf := vpn.Config{
		Mode:         *mode,
		ServerAddr:   *serverAddr,
		ServerPubKey: *serverPubKey,
		KeyPath:      *keyPath,
		IdentityPath: *identityPath,
		TUN: tun.Config{
			Name:  *tunName,
			Addr:  *tunAddr,
			Route: *tunRoute,
		},
	}
	log.Printf("conf: %+v", conf)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := vpn.Run(ctx, conf); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	log.Println("vpn exited")
}
