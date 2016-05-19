ipsec auto --up  road-east-ipv4-psk-ikev2
ipsec auto --up  road-east-ipv6-psk-ikev2
ping -n -c 2 -I 192.0.1.254 192.0.2.254
ping -n -c 2 -I 192.0.11.254 192.0.2.254
ping6 -n -c 2 2001:db8:1:2::23
ipsec whack --trafficstatus
echo done
