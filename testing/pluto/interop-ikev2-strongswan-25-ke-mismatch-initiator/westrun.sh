ipsec auto --up westnet-eastnet-ikev2 | grep -v libcurl
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo done
