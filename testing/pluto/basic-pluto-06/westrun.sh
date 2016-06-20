ipsec auto --up  westnet-eastnet-ipv4-psk
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
