package main

import (
	"flag"
	"log"

	"vpn0/tun"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// cli options
var mode = flag.String("m", "client", "VPN mode: client, server or test")
var tunName = flag.String("tun-name", "vpn0", "TUN device name")
var tunAddr = flag.String("tun-addr", "10.100.200.1/24", "TUN device primary addr")
var tunRoute = flag.String("tun-route", "", "TUN device route")

func main() {
	flag.Parse()
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

	switch *mode {
	// mode "test" reads from tun, parses the packet and dumps some contents to stdout.
	//
	// It leaves the caller hanging.
	case "test":
		for {
			b := make([]byte, 2048) // MTU x2
			n, err := td.Read(b)
			if err != nil {
				// fatal
				log.Printf("tun device read err: %v", err)
				break
			}
			// gopacket.Default is safe but slow
			p := gopacket.NewPacket(b[:n], layers.LayerTypeIPv4, gopacket.Default)
			// only allow TCP
			if v := p.Layer(layers.LayerTypeTCP); v == nil {
				log.Println("not TCP. Ignore.")
				continue
			}
			// only allow IPv4
			ipLayer := p.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				log.Println("not IPv4. Ignore.")
				continue
			}
			ipPacket, ok := ipLayer.(*layers.IPv4)
			if !ok {
				log.Println("bad IPv4 packet. Ignore.")
				continue
			}
			// log some data from the IP packet
			log.Printf("got %s to %s", ipPacket.SrcIP, ipPacket.DstIP)
		}
	case "client":
		log.Println("not implemented")
	case "server":
		log.Println("not implemented")
	default:
		log.Println("unknown mode")
	}
}
