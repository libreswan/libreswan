ipsec auto --up northnet-eastnet-nat
../../guestbin/ping-once.sh --down -I 198.18.66.254 192.0.2.254
echo done
