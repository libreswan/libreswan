strongswan up roadnet-eastnet-ikev2 | grep -v resolvconf
../../guestbin/ping-once.sh --up -I 192.0.2.1 192.1.2.23
echo done
