#!/bin/bash

# Quick and dirty kernel routing configs
#
# Note! Some components are hardcoded

# enable routing
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "routing enabled"

# disable filter
sysctl -w net.ipv4.conf.all.rp_filter=0
echo "filter disabled"

# NAT
iptables -t nat -A POSTROUTING -s 10.100.3.0/24 -o enp6s0 -j MASQUERADE
echo "NAT table configured"

# forwarding
iptables -A FORWARD -i vpn0 -o enp6s0 -j ACCEPT
iptables -A FORWARD -i enp6s0 -o vpn0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
