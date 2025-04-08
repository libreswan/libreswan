ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec _kernel state
ipsec _kernel policy
grep "fragment number" /tmp/pluto.log
echo done
