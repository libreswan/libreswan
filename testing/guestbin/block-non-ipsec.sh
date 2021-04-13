#!/bin/sh

# Allow ssh to get back into VMs from host after test ran
iptables -A INPUT -p tcp --dport  22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport  22 -j ACCEPT
# Drop all non-IPsec traffic
iptables -A INPUT  -p udp --dport 500 -j ACCEPT
iptables -A OUTPUT -p udp --sport 500 -j ACCEPT
iptables -A INPUT  -p udp --dport 4500 -j ACCEPT
iptables -A OUTPUT -p udp --sport 4500 -j ACCEPT
iptables -A INPUT  -p esp -j ACCEPT
iptables -A OUTPUT -p esp -j ACCEPT
iptables -A INPUT  -m policy --pol none --dir in  -j DROP
iptables -A OUTPUT -m policy --pol none --dir out -j DROP
