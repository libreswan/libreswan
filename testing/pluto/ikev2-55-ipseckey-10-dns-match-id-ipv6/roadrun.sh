# there should be only one pub key not road.
ipsec listpubkeys
ipsec up road-east-ikev2
# there should be two public keys. including road
../../guestbin/ping-once.sh --up -I 2001:db8:1:3::209 2001:db8:1:2::23
ipsec trafficstatus
echo done
