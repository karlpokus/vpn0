build:
	go build -o bin ./cmd/vpn
	go build -o bin ./cmd/target

push:
	lxc file push bin vpn0-client/tmp -pr
	lxc file push bin vpn0-server/tmp -pr
	lxc file push bin vpn0-target/tmp -pr

test:
	go test ./...

init:
	cp -iv kernel-routing.sh bin

	lxc network create vpn0-public ipv4.address=10.100.1.1/24 ipv4.nat=false ipv6.address=none ipv6.nat=false
	lxc network create vpn0-private ipv4.address=10.100.2.1/24 ipv4.nat=false ipv6.address=none ipv6.nat=false

	lxc launch ubuntu:24.04 vpn0-client --vm
	lxc launch ubuntu:24.04 vpn0-server --vm
	lxc launch ubuntu:24.04 vpn0-target --vm

	lxc network attach vpn0-public vpn0-client eth0
	lxc network attach vpn0-public vpn0-server eth0
	lxc network attach vpn0-private vpn0-server eth1
	lxc network attach vpn0-private vpn0-target eth0

	lxc network acl create vpn0-public-acl
	lxc network set vpn0-public security.acls=vpn0-public-acl
	lxc network acl rule add vpn0-public-acl ingress action=allow source=0.0.0.0/0 destination=10.100.1.105
	lxc network acl rule add vpn0-public-acl ingress action=drop source=10.100.2.0/24 destination=10.100.1.105

	lxc network acl create vpn0-private-acl
	lxc network set vpn0-private security.acls=vpn0-private-acl
	lxc network acl rule add vpn0-private-acl ingress action=allow source=10.100.2.10 destination=10.100.2.0/24
	lxc network acl rule add vpn0-private-acl ingress action=allow source=10.100.2.0/24 destination=10.100.2.10
	lxc network acl rule add vpn0-private-acl ingress action=drop source=0.0.0.0/0 destination=10.100.2.0/24