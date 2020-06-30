ipsec auto --up road-eastnet-ikev2
../../pluto/bin/ping-once.sh --up 192.0.2.254
ipsec whack --impair send-keepalive:1
../../pluto/bin/ping-once.sh --up 192.0.2.254
../bin/ipsec-look.sh
echo done
