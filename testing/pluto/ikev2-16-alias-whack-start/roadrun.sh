#ipsec auto --up road-east-ipv4-psk-ikev2
ipsec auto --status | grep road-east
ipsec auto --up  road-east-ipv4-psk-ikev2
ping -n -c 2 -I 192.0.1.254 192.0.2.254
ping -n -c 2 -I 192.0.11.254 192.0.2.254
ipsec whack --trafficstatus
echo done
