ipsec auto --up road-1
ipsec auto --up road-2
../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
echo done
