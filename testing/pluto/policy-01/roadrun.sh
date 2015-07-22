#!/bin/sh

: check out config
ipsec eroute

ping -n -c 1 192.1.2.23

: transfer some data
nc -w 5 192.1.2.23 4

ipsec eroute | grep -l tun

