#!/bin/sh

# get to the 192.0.1.0/24 network via 192.1.3.45
route delete -net 192.0.1.0 netmask 255.255.255.0
route add -net 192.0.1.0 netmask 255.255.255.0 gw 192.9.4.45

# also make sure that the sunrise network is in fact behind .23, because
route delete -net 192.0.2.0 netmask 255.255.255.0
route add -net 192.0.2.0 netmask 255.255.255.0 gw 192.1.2.23

# now start named
named

# and services
inetd
