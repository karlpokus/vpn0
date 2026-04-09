# vpn0
Userspace vpn for fun and profit.

Topology: caller <-> tun <-> vpn-client <-> vpn-server <-> tun (-> magic kernel routing) <-> target

# Local dev

Networks
- public: 10.100.1.0/24
- private: 10.100.2.0/24
- vpn: 10.100.3.0/24

VMs
- client host: member of public only, runs vpn in client mode.
- server host: member of public and private, runs vpn in server mode relying on kernel routing configs.
- target host: member of private only, runs a test target HTTP server.

````sh
# Create all the things
#
# Note! This as a guideline. Might not be complete.
# Especially the 2nd interface on the server did
# not attach properly one time.
$ make init
# Build and push artifacts
$ make build
$ make push
# Run vpn client
$ /tmp/bin/vpn -m client -tun-addr 10.100.3.1/24 -tun-route 10.100.2.0/24 -udp-server-addr 10.100.1.105:8989
# Run vpn server
$ /tmp/bin/vpn -m server -tun-addr 10.100.3.254/24 -udp-server-addr 10.100.1.105:8989
# configure kernel routing
$ /tmp/bin/kernel-routing.sh
# Run test target
$ /tmp/bin/target -h 10.100.2.178 -p 7777
# Call test target using HTTP
$ curl http://10.100.2.178:7777
# or TCP stream
nc -l -n -v -s 10.100.2.178 -p 7777
nc -nv 10.100.2.178 7777
````

ACL test

````bash
1. client ping server public IP - OK
2. client ping server private IP or target private IP - Not OK
3. server ping client public IP - OK
4. server ping target private IP - OK
5. target ping server public IP - Not OK
6. target ping server private IP - OK
````

# Todos
- [x] tun device test mode
- [x] replace test mode with ICMP support
- [x] graceful shutdown
- [x] client
- [x] server
- [ ] kernel routing config in go
- [ ] encryption
- [ ] config file support
- [x] support multiple vpn clients
