# vpn0
Userspace vpn for fun and profit.

Topology: caller <-> tun <-> vpn-client <-> vpn-server <-> tun (-> magic kernel routing) <-> target

# Local dev

````sh
# build and run in test mode
$ go build -o bin ./cmd/vpn
$ sudo bin/vpn -m client
# run callers (UDP, TCP)
$ echo hi | nc -u 10.100.200.2 8989 -v
$ curl http://10.100.200.2:8989
````

# Todos
- [x] tun device test mode
- [x] replace test mode with ICMP support
- [ ] graceful shutdown
- [ ] client
- [ ] server
