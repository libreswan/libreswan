# there should be only one pub key not road.
ipsec auto --listpubkeys
ipsec auto --up  north-east
# there should be two public keys. including road
ping -n -c 4 -I 192.1.3.33 192.1.2.23
ipsec whack --trafficstatus
echo done
