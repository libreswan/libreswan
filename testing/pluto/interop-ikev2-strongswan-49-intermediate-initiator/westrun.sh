strongswan up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
swanctl --rekey --ike westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
strongswan down westnet-eastnet-ikev2
echo done
