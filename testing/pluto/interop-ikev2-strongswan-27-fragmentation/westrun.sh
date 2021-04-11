ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ipsec-look.sh
grep "fragment number" /tmp/pluto.log
echo done
