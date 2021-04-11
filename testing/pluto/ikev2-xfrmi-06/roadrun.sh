ipsec auto --up road
ping -n -q -c 2 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
echo done
