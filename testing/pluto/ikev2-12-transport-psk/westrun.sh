ipsec auto --up  ipv4-psk-ikev2-transport
ping -n -c 4 -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
echo done
