ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec status | grep ticket
ipsec whack --suspend --name westnet-eastnet-ipv4-psk-ikev2
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
egrep "PLUTO_INBYTES='[1-9][0-9]*'" /tmp/pluto.log > /dev/null || echo "Error: traffic counters not passed to updown!"
echo done
