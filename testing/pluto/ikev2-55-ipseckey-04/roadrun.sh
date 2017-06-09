# there should be only one pub key not road.
ipsec auto --listpubkeys
ipsec auto --up  road-east-ikev2
# there should be two public keys. including road
ping -n -c 4 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done
