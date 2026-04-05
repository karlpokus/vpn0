package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

var host = flag.String("h", "localhost", "HTTP host")
var port = flag.String("p", "8889", "HTTP port")

func main() {
	flag.Parse()
	err := startServer(net.JoinHostPort(*host, *port))
	if err != nil {
		log.Printf("server start err: %v", err)
	}
}

func startServer(addr string) error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		msg := fmt.Sprintf("Hello %s", r.RemoteAddr)
		log.Println(msg)
		fmt.Fprintln(w, msg)
	})
	log.Printf("starting HTTP server on %s", addr)
	return http.ListenAndServe(addr, nil)
}
