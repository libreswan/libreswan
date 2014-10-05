#!/bin/sh

: turn on debugging
ipsec whack --debug-control --debug-oppo --debug-dns

: check out config
ipsec eroute

: use oppohere/oppothere to see negotiation
ipsec whack --oppohere 192.1.3.209 --oppothere 192.0.2.2

: try again with ping
ping -n -c 2 192.0.2.2

if ! ipsec eroute | grep -q drop ; then echo 'MISSING DROP!' ; ipsec eroute ; ipsec auto --status ; else echo 'found expected drop' ; fi


