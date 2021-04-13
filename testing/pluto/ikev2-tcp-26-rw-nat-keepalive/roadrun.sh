ipsec auto --up road-eastnet-ikev2
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --impair send-keepalive:1
../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ipsec-look.sh
echo done
