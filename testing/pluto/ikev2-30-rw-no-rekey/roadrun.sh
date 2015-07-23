#!/bin/sh
ping -q -n -c 2 192.1.2.23
ipsec auto --up road-east-x509-ipv4
echo "sleep 110 seconds"
sleep 60
sleep 50
ping -q -n -c 8 -I 192.0.2.100 192.1.2.23
ipsec status
echo end
