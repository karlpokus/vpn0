package main

import (
	"context"
	"flag"
	"log"
	"net"

	"vpn0/tun"
	"vpn0/vpn"
)

// cli options
var mode = flag.String("m", "client", "VPN mode: client or server")
var tunName = flag.String("tun-name", "vpn0", "TUN device name")
var tunAddr = flag.String("tun-addr", "", "TUN device primary addr")
var tunRoute = flag.String("tun-route", "", "TUN device route")
var UDPLocalAddr = flag.String("udp-laddr", "", "UDP local addr: host:port")
var UDPRemoteAddr = flag.String("udp-raddr", "", "UDP remote addr: host:port")

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Printf("mode: %s", *mode)

	// TUN device config
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

	// UDP conn config
	conn, err := newUDPConn(*UDPLocalAddr, *UDPRemoteAddr)
	if err != nil {
		// fatal
		log.Println(err)
		flag.PrintDefaults()
		return
	}
	defer conn.Close()
	log.Printf("UDP connection to %s created", *UDPRemoteAddr)

	// VPN startup
	v := vpn.New(*mode)
	if err := v.Pipe(ctx, td, conn); err != nil {
		log.Println(err)
	}
}

// newUDPConn creates a new UDP connection to the peer.
func newUDPConn(laddr, raddr string) (*net.UDPConn, error) {
	l, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	r, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", l, r)
}
